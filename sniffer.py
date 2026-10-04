"""
img_sniffer.py v2 - mitmproxy addon: deep media capture from proxied traffic.

Run:  mitmdump -s img_sniffer.py                          # passive (default)
      mitmdump -s img_sniffer.py --set sniff_mode=crawler  # active crawler
      (or env SNIFF_MODE=crawler)

MODES
  passive  only what the browser actually loads for the page you are looking at.
           No extra requests, no extra traffic. Still decodes data: URIs and inline <svg>.
  crawler  everything in passive PLUS discovered URLs are fetched and parsed
           recursively (lazy images, CSS assets, srcset variants, manifests...).
           Fetches wait `crawl_delay` seconds and skip anything the browser loaded
           meanwhile, so nothing is downloaded twice.

What it does
  PASSIVE   every response is sniffed by magic bytes (not Content-Type / URL), so
            mislabeled files, extension-less URLs and octet-stream downloads are caught.
            Images, video, audio, documents, fonts (+ optional archives/other).
  DEEP      HTML / CSS / JS / JSON / XML / manifest / m3u8 responses are parsed for:
            <img src|srcset>, <picture>, <video poster>, lazy-load attrs (data-src,...),
            meta og:image, link icons/manifest/stylesheets, <a href> to media/docs,
            CSS url() / @import / image-set, any quoted media URL inside JS/JSON,
            base64 + percent-encoded data: URIs (decoded and saved), inline <svg>.
  CRAWL     discovered URLs are fetched (depth-limited, concurrency-limited) and
            parsed again, so lazy-loaded / never-scrolled-into-view assets are caught.
  FRESH     conditional headers are stripped so cached assets (304) come back as 200.
  OTHER     WebSocket frames and (optional) uploads are scanned too.
  MULTICORE all CPU work runs in a process pool; the proxy hook returns immediately.
            Worker code is embedded below and written to a temp module at startup.

All settings are in CFG. Worker count: SNIFF_WORKERS=N
"""
import asyncio
import csv
import logging
import os
import re
import shutil
import sys
import tempfile
import time
import multiprocessing as mp
from collections import Counter, OrderedDict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

from mitmproxy import http, ctx

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------
CFG = {
    "out_dir": "sniffed_media",        # <out_dir>/<category>/<host>/<name>_<sha10>.<ext>
    "out_csv": "media.csv",
    "group_by_host": True,

    # --- what to keep ---
    "categories": {"image": True, "video": True, "audio": True, "document": True,
                   "font": True, "archive": False, "other": False},
    "min_bytes": {"image": 200, "video": 1024, "audio": 1024, "document": 512,
                  "font": 512, "archive": 512, "other": 512},
    "max_bytes": {"image": 50 << 20, "video": 300 << 20, "audio": 100 << 20,
                  "document": 100 << 20, "font": 20 << 20, "archive": 200 << 20,
                  "other": 50 << 20},
    "formats_allow": [],               # e.g. ["png","jpg","pdf"]; empty = all
    "formats_block": [],               # e.g. ["ico"]
    # image-only geometry filters (set higher to drop icons / tracking pixels)
    "min_width": 16, "min_height": 16, "min_pixels": 256,
    "max_aspect": 0,                   # e.g. 20 drops thin banner strips; 0 = off
    "dedupe_by_hash": True,            # content-addressed marker files in <out_dir>/.hashes

    # --- request filters (main process, zero CPU cost) ---
    "methods": ("GET",),
    "status_codes": (200,),            # a 206 that covers the whole file is also accepted
    "host_allow": [],                  # regex list; empty = all
    "host_block": [
        r"(^|\.)doubleclick\.net$", r"(^|\.)google-analytics\.com$",
        r"(^|\.)googletagmanager\.com$", r"(^|\.)googlesyndication\.com$",
        r"(^|\.)scorecardresearch\.com$", r"(^|\.)adnxs\.com$", r"(^|\.)criteo\.",
    ],
    "url_block": [],                   # regex on full URL
    "referer_allow": [],               # regex on Referer for passive capture

    # --- depth ---
    "extract_text": True,              # parse html/css/js/json/xml for data URIs + inline svg
    "inline_svg": True,                # save <svg>...</svg> blocks found in HTML
    "max_data_uris": 200,
    "fetch_referenced": True,          # CRAWL: download discovered URLs (bypasses the proxy)
    "max_depth": 3,                    # page(0) -> css/json(1) -> assets(2) -> nested(3)
    "crawl_css": True,                 # follow stylesheets + @import
    "crawl_js": False,                 # follow <script src> (heavy; finds JS-built URLs)
    "fetch_same_site_only": False,
    "max_fetches": 20000,              # hard cap per run
    "max_urls_per_doc": 500,
    "fetch_timeout": 12,
    "fetch_concurrency": 12,
    "fetch_max_bytes": 100 << 20,
    "max_text_bytes": 5 << 20,
    "crawl_delay": 3.0,                # crawler: wait so the browser can load its own files first

    # --- traffic tweaks ---
    "strip_conditional": True,         # drop If-None-Match / If-Modified-Since -> no 304s
    "strip_range": True,               # drop Range for non-stream types -> no 206 fragments
    "websocket": True,
    "capture_uploads": False,          # also scan request bodies / multipart parts

    # --- runtime ---
    "workers": int(os.environ.get("SNIFF_WORKERS", max(1, (os.cpu_count() or 2) - 1))),
    "max_pending": 256,
    "title_cache": 3000,
}

PRESETS = {
    "passive": {
        "fetch_referenced": False, "crawl_css": False, "crawl_js": False, "max_depth": 0,
    },
    "crawler": {
        "fetch_referenced": True, "crawl_css": True, "crawl_js": False, "max_depth": 3,
    },
}

EXTS = {
    "image": ["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "avif", "heic", "heif",
              "tif", "tiff", "ico", "cur", "jp2", "jxl", "psd", "dds", "icns"],
    "video": ["mp4", "m4v", "webm", "mkv", "mov", "avi", "flv", "wmv", "3gp", "ts",
              "m4s", "mpg", "mpeg", "m3u8", "mpd"],
    "audio": ["mp3", "m4a", "aac", "ogg", "oga", "opus", "wav", "flac", "mid", "midi"],
    "document": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
                 "odp", "rtf", "epub", "ps"],
    "font": ["woff", "woff2", "ttf", "otf", "eot", "ttc"],
    "archive": ["zip", "gz", "tgz", "rar", "7z", "bz2", "xz", "tar", "zst", "jar", "apk"],
    "other": ["wasm"],
}
STREAM_EXTS = set(EXTS["video"] + EXTS["audio"])

CSV_HEADER = ["index", "category", "filename", "url", "source", "depth", "size_bytes",
              "width", "height", "format", "sha256", "page_url", "page_title", "timestamp"]

# ----------------------------------------------------------------------------
# WORKER CODE (runs in child processes)
# ----------------------------------------------------------------------------
WORKER_SRC = r'''
import base64, binascii, gzip, hashlib, os, re, struct, urllib.request, zlib
from urllib.parse import urljoin, urlparse, unquote_to_bytes

AMBIG = {"ole": ("doc", "xls", "ppt", "msg", "vsd"),
         "zip": ("zip", "jar", "apk", "xpi", "war"),
         "ogg": ("ogg", "oga", "ogv", "opus"),
         "mp4": ("mp4", "m4v", "mov")}

def _ttf(h):
    if len(h) < 16: return False
    nt = struct.unpack(">H", h[4:6])[0]
    if not 1 <= nt <= 64: return False
    tabs = h[12:12 + 16 * nt]
    return any(t in tabs for t in (b"cmap", b"head", b"glyf", b"OS/2", b"name"))

def _mpeg_audio(h):
    b1, b2 = h[1], h[2]
    return ((b1 & 0xE0) == 0xE0 and ((b1 >> 3) & 3) != 1 and ((b1 >> 1) & 3) != 0
            and (b2 >> 4) != 15 and ((b2 >> 2) & 3) != 3)

def sniff(d):
    """-> (category, format) or None, from magic bytes only."""
    h = d[:4096]; n = len(h)
    if n < 4: return None
    p4 = h[:4]
    if h[:8] == b"\x89PNG\r\n\x1a\n": return ("image", "png")
    if h[:3] == b"\xff\xd8\xff": return ("image", "jpeg")
    if h[:6] in (b"GIF87a", b"GIF89a"): return ("image", "gif")
    if p4 == b"RIFF" and n >= 12:
        t = h[8:12]
        if t == b"WEBP": return ("image", "webp")
        if t == b"WAVE": return ("audio", "wav")
        if t == b"AVI ": return ("video", "avi")
        return None
    if h[:2] == b"BM" and n > 30 and h[6:10] == b"\x00\x00\x00\x00": return ("image", "bmp")
    if p4 == b"\x00\x00\x01\x00": return ("image", "ico")
    if p4 == b"\x00\x00\x02\x00": return ("image", "cur")
    if p4 in (b"II*\x00", b"MM\x00*"): return ("image", "tiff")
    if p4 == b"8BPS": return ("image", "psd")
    if p4 == b"DDS ": return ("image", "dds")
    if p4 == b"icns": return ("image", "icns")
    if h[:12] == b"\x00\x00\x00\x0cjP  \r\n\x87\n": return ("image", "jp2")
    if h[:2] == b"\xff\x0a" or h[:12] == b"\x00\x00\x00\x0cJXL \r\n\x87\n": return ("image", "jxl")
    if h[4:8] == b"ftyp":
        b = h[8:12]
        if b in (b"avif", b"avis"): return ("image", "avif")
        if b in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"heim", b"heis"):
            return ("image", "heic")
        if b in (b"M4A ", b"M4B ", b"M4P "): return ("audio", "m4a")
        if b[:2] == b"3g": return ("video", "3gp")
        if b == b"qt  ": return ("video", "mov")
        return ("video", "mp4")
    if p4 == b"\x1a\x45\xdf\xa3": return ("video", "webm" if b"webm" in h[:64] else "mkv")
    if p4[:3] == b"FLV" and h[3] == 1: return ("video", "flv")
    if h[:8] == b"\x30\x26\xb2\x75\x8e\x66\xcf\x11": return ("video", "wmv")
    if p4 == b"\x00\x00\x01\xba": return ("video", "mpg")
    if h[0] == 0x47 and n > 188 and h[188] == 0x47: return ("video", "ts")
    if p4 == b"OggS": return ("audio", "ogg")
    if p4[:3] == b"ID3": return ("audio", "mp3")
    if p4 == b"fLaC": return ("audio", "flac")
    if p4 == b"MThd": return ("audio", "mid")
    if h[:5] == b"#!AMR": return ("audio", "amr")
    if h[0] == 0xFF and n >= 4:
        if h[1] in (0xF1, 0xF9): return ("audio", "aac")
        if _mpeg_audio(h): return ("audio", "mp3")
    if h[:5] == b"%PDF-": return ("document", "pdf")
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": return ("document", "ole")
    if h[:5] == b"{\\rtf": return ("document", "rtf")
    if h[:4] == b"%!PS": return ("document", "ps")
    if p4 == b"PK\x03\x04":
        if b"application/epub+zip" in h: return ("document", "epub")
        if b"application/vnd.oasis.opendocument" in h: return ("document", "odf")
        if b"[Content_Types].xml" in h or b"_rels/" in h:
            if b"word/" in h: return ("document", "docx")
            if b"xl/" in h: return ("document", "xlsx")
            if b"ppt/" in h: return ("document", "pptx")
        return ("archive", "zip")
    if p4 == b"wOFF": return ("font", "woff")
    if p4 == b"wOF2": return ("font", "woff2")
    if p4 == b"OTTO": return ("font", "otf")
    if p4 == b"ttcf": return ("font", "ttc")
    if p4 == b"\x00\x01\x00\x00" and _ttf(h): return ("font", "ttf")
    if n > 36 and h[34:36] == b"LP": return ("font", "eot")
    if h[:2] == b"\x1f\x8b": return ("archive", "gz")
    if p4[:3] == b"BZh": return ("archive", "bz2")
    if h[:6] == b"7z\xbc\xaf\x27\x1c": return ("archive", "7z")
    if h[:6] == b"Rar!\x1a\x07": return ("archive", "rar")
    if h[:6] == b"\xfd7zXZ\x00": return ("archive", "xz")
    if p4 == b"\x28\xb5\x2f\xfd": return ("archive", "zst")
    if n > 262 and h[257:262] == b"ustar": return ("archive", "tar")
    if p4 == b"\x00asm": return ("other", "wasm")
    if h[:15] == b"SQLite format 3": return ("other", "sqlite")
    hl = h[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if hl.startswith(b"<svg") or (hl.startswith((b"<?xml", b"<!doctype svg"))
                                  and b"<svg" in hl and b"<html" not in hl):
        return ("image", "svg")
    return None

def _jpeg(d):
    i, n = 2, len(d)
    sof = {0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF}
    while i + 9 < n:
        if d[i] != 0xFF: i += 1; continue
        m = d[i + 1]
        if m == 0xFF: i += 1; continue
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7: i += 2; continue
        if m in sof:
            h, w = struct.unpack(">HH", d[i + 5:i + 9]); return w, h
        i += 2 + struct.unpack(">H", d[i + 2:i + 4])[0]
    return None

def _webp(d):
    c = d[12:16]
    if c == b"VP8 ":
        w, h = struct.unpack("<HH", d[26:30]); return w & 0x3FFF, h & 0x3FFF
    if c == b"VP8L":
        b = int.from_bytes(d[21:25], "little")
        return (b & 0x3FFF) + 1, ((b >> 14) & 0x3FFF) + 1
    if c == b"VP8X":
        return int.from_bytes(d[24:27], "little") + 1, int.from_bytes(d[27:30], "little") + 1
    return None

def dims(fmt, d):
    try:
        if fmt == "png": return struct.unpack(">II", d[16:24])
        if fmt == "gif": return struct.unpack("<HH", d[6:10])
        if fmt == "bmp":
            w, h = struct.unpack("<ii", d[18:26]); return abs(w), abs(h)
        if fmt == "jpeg": return _jpeg(d)
        if fmt == "webp": return _webp(d)
    except Exception:
        pass
    return None

def _safe(s, limit=80):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)[:limit] or "x"

def save_blob(data, url, sn, cfg, source, hint=None):
    cat, fmt = sn
    if not cfg["categories"].get(cat): return {"skip": "cat_" + cat}
    n = len(data)
    if n < cfg["min_bytes"][cat]: return {"skip": "too_small"}
    if n > cfg["max_bytes"][cat]: return {"skip": "too_large"}
    path_url = urlparse(url).path
    urlext = os.path.splitext(path_url)[1][1:].lower()
    ext = "jpg" if fmt == "jpeg" else ("odf" if fmt == "odf" else fmt)
    if fmt in AMBIG and urlext in AMBIG[fmt]: ext = urlext
    if fmt == "odf" and urlext in ("odt", "ods", "odp"): ext = urlext
    if cfg["formats_allow"] and ext not in cfg["formats_allow"] and fmt not in cfg["formats_allow"]:
        return {"skip": "format_not_allowed"}
    if ext in cfg["formats_block"] or fmt in cfg["formats_block"]:
        return {"skip": "format_blocked"}
    w = h = 0
    if cat == "image":
        dm = dims(fmt, data)
        if dm:
            w, h = dm
            if w < cfg["min_width"] or h < cfg["min_height"] or w * h < cfg["min_pixels"]:
                return {"skip": "too_small_px"}
            if cfg["max_aspect"] and max(w, h) / max(1, min(w, h)) > cfg["max_aspect"]:
                return {"skip": "aspect"}
    sha = hashlib.sha256(data).hexdigest()
    out = cfg["out_dir"]
    marker = None
    if cfg["dedupe_by_hash"]:
        md = os.path.join(out, ".hashes"); os.makedirs(md, exist_ok=True)
        marker = os.path.join(md, sha)
        try: os.close(os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError: return {"skip": "duplicate"}
    host = _safe(urlparse(url).hostname or "unknown")
    stem = hint or _safe(os.path.splitext(os.path.basename(path_url))[0], 60)
    folder = os.path.join(out, cat, host) if cfg["group_by_host"] else os.path.join(out, cat)
    try:
        os.makedirs(folder, exist_ok=True)
        fpath = os.path.join(folder, "%s_%s.%s" % (stem, sha[:10], ext))
        tmp = fpath + ".part%d" % os.getpid()
        with open(tmp, "wb") as f: f.write(data)
        os.replace(tmp, fpath)
    except OSError:
        if marker:
            try: os.remove(marker)
            except OSError: pass
        return {"skip": "write_error"}
    return {"category": cat, "fmt": ext, "w": w, "h": h, "size": n, "sha256": sha,
            "path": os.path.relpath(fpath, out), "url": url, "source": source}

# ---------------------------------------------------------------- text discovery
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_ATTR = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
_B64 = re.compile(r"data:([\w.+/-]{0,60})((?:;[\w.=+-]{1,40})*);base64,([A-Za-z0-9+/_=-]{100,})")
_DSVG = re.compile(r"data:image/svg\+xml(?:;[\w=.-]+)*,([^\"'`)]{20,})")
_INSVG = re.compile(r"<svg\b.*?</svg>", re.S | re.I)
_IMPORT = re.compile(r"""@import\s+(?:url\()?\s*['"]?([^'")\s;]+)""", re.I)
LAZY = {"data-src", "data-original", "data-lazy-src", "data-lazy", "data-image", "data-img",
        "data-bg", "data-background", "data-background-image", "data-poster", "data-full",
        "data-large", "data-zoom-image", "data-hi-res", "data-thumb", "data-thumbnail",
        "data-fallback-src", "data-url", "data-echo", "data-lazyload", "data-srcset",
        "data-image-src", "data-big", "data-bigsrc"}
MEDIA_TAGS = {"img", "source", "video", "audio", "embed", "object", "input", "image",
              "picture", "track"}
_RX = {}

def _rx(cfg):
    key = tuple(cfg["scan_exts"])
    r = _RX.get(key)
    if r is None:
        ex = "|".join(sorted({re.escape(e) for e in key}, key=len, reverse=True))
        r = {
            "quoted": re.compile(r"""["'`]([^"'`\s<>\\]{1,1500}?\.(?:%s)(?:[?#][^"'`\s<>\\]{0,1000})?)["'`]""" % ex, re.I),
            "abs": re.compile(r"""https?://[^\s"'`<>()\\]{1,1500}?\.(?:%s)(?![\w.-])(?:\?[^\s"'`<>()\\]{0,1000})?""" % ex, re.I),
            "cssurl": re.compile(r"""url\(\s*(['"]?)([^)'"]{1,2000}?)\1\s*\)""", re.I),
            "tag": re.compile(r"<([a-zA-Z][\w:-]*)\b([^>]*)>"),
            "pathext": re.compile(r"\.(?:%s)$" % ex, re.I),
        }
        _RX[key] = r
    return r

def text_kind(ctype, url=""):
    ct = (ctype or "").split(";")[0].strip().lower()
    if "html" in ct: return "html"
    if ct == "text/css": return "css"
    if "javascript" in ct or "ecmascript" in ct: return "js"
    if "json" in ct: return "json"
    if "mpegurl" in ct: return "m3u8"
    if "xml" in ct and not ct.startswith("image/"): return "xml"
    if ct == "text/plain": return "text"
    if ct in ("", "application/octet-stream", "binary/octet-stream"):
        p = urlparse(url).path.lower()
        for e, k in ((".css", "css"), (".js", "js"), (".mjs", "js"), (".json", "json"),
                     (".webmanifest", "json"), (".html", "html"), (".htm", "html"),
                     (".xml", "xml"), (".mpd", "xml"), (".m3u8", "m3u8")):
            if p.endswith(e): return k
    return None

def _decode_b64(s):
    s = s.replace("-", "+").replace("_", "/")
    try: return base64.b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError): return None

def discover(body, kind, ctype, base, cfg, res):
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
    try: text = body.decode(m.group(1) if m else "utf-8", errors="replace")
    except LookupError: text = body.decode("utf-8", errors="replace")
    text = (text.replace("\\/", "/").replace("\\u002F", "/").replace("\\u0026", "&")
                .replace("&amp;", "&").replace("&#x2F;", "/"))
    if kind == "html":
        t = _TITLE.search(text)
        if t: res["title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:200]
        bm = re.search(r"<base[^>]+href=[\"']([^\"']+)", text, re.I)
        if bm: base = urljoin(base, bm.group(1))

    # --- data: URIs -> decode + save
    n = 0; cap = cfg["max_data_uris"]
    def emit(data, tag, hint):
        nonlocal n
        sn = sniff(data)
        if not sn: return
        n += 1
        mm = save_blob(data, "%s#%s-%d" % (base, tag, n), sn, cfg, tag, hint=hint)
        mm["page"] = base
        res["metas"].append(mm)
    if "data:" in text:
        for dm in _B64.finditer(text):
            if n >= cap: break
            data = _decode_b64(dm.group(3))
            if data: emit(data, "datauri", "inline")
        text = _B64.sub("", text)
        for dm in _DSVG.finditer(text):
            if n >= cap: break
            emit(unquote_to_bytes(dm.group(1)), "datauri", "inline")
        text = _DSVG.sub("", text)
    if kind == "html" and cfg["inline_svg"]:
        k = 0
        for sm in _INSVG.finditer(text):
            k += 1
            if k > 300: break
            raw = sm.group(0).encode("utf-8", "replace")
            if b"xmlns=" not in raw[:300]:
                raw = re.sub(rb"<svg", b'<svg xmlns="http://www.w3.org/2000/svg"', raw, count=1, flags=re.I)
            mm = save_blob(raw, "%s#svg-%d" % (base, k), ("image", "svg"), cfg, "inline_svg", hint="inline_svg")
            mm["page"] = base
            res["metas"].append(mm)

    if not cfg["fetch_referenced"]:
        return
    # --- URL discovery
    rx = _rx(cfg); urls = []; seen = set()
    def add(u):
        if not u: return
        u = u.strip().strip("\"'")
        if (not u or len(u) > 2000 or u[0] in "#{$" or "${" in u or "{{" in u
                or "%s" in u or "<" in u
                or u.startswith(("data:", "javascript:", "blob:", "about:", "mailto:", "tel:"))):
            return
        try: a = urljoin(base, u)
        except ValueError: return
        if a.startswith(("http://", "https://")):
            a = a.split("#", 1)[0]
            if a not in seen: seen.add(a); urls.append(a)
    if kind == "html":
        for tm in rx["tag"].finditer(text):
            tag = tm.group(1).lower()
            attrs = {k.lower(): (a or b or c) for k, a, b, c in _ATTR.findall(tm.group(2))}
            for k, v in attrs.items():
                if "srcset" in k:
                    for part in v.split(","):
                        add(part.strip().split(" ")[0])
                elif k in LAZY:
                    add(v.strip().split(" ")[0])
                elif k == "src":
                    if tag in MEDIA_TAGS or (tag == "script" and cfg["crawl_js"]): add(v)
                elif k in ("poster", "background") or (k == "data" and tag == "object"):
                    add(v)
                elif k == "xlink:href" or (k == "href" and tag in ("image", "use")):
                    add(v)
                elif k == "href":
                    if tag == "link":
                        rel = (attrs.get("rel") or "").lower()
                        if ("icon" in rel or "image_src" in rel or "manifest" in rel
                                or ("preload" in rel and (attrs.get("as") or "") in ("image", "font", "video", "audio"))
                                or ("stylesheet" in rel and cfg["crawl_css"])):
                            add(v)
                    elif tag in ("a", "area") and rx["pathext"].search(urlparse(v).path):
                        add(v)
                elif k == "content" and tag == "meta":
                    key = (attrs.get("property") or attrs.get("name") or attrs.get("itemprop") or "").lower()
                    if any(w in key for w in ("image", "video", "audio", "tileimage")): add(v)
    for mm in rx["cssurl"].finditer(text): add(mm.group(2))
    for mm in rx["quoted"].finditer(text): add(mm.group(1))
    for mm in rx["abs"].finditer(text): add(mm.group(0))
    if kind == "css" and cfg["crawl_css"]:
        for mm in _IMPORT.finditer(text): add(mm.group(1))
    if kind == "m3u8" or base.lower().split("?")[0].endswith(".m3u8"):
        for line in text.splitlines():
            line = line.strip()
            if line and line[0] != "#": add(line)
    if kind == "xml":
        for mm in re.finditer(r"<BaseURL>([^<]+)</BaseURL>", text): add(mm.group(1))
    res["urls"] = urls[:cfg["max_urls_per_doc"]]

def handle(body, url, ctype, cfg, source="http"):
    res = {"metas": [], "urls": [], "title": ""}
    sn = sniff(body)
    if sn:
        res["metas"].append(save_blob(body, url, sn, cfg, source))
        return res
    kind = text_kind(ctype, url)
    if kind and cfg["extract_text"] and len(body) <= cfg["max_text_bytes"]:
        discover(body, kind, ctype, url, cfg, res)
    return res

def fetch_handle(url, headers, cfg):
    empty = {"metas": [], "urls": [], "title": ""}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=cfg["fetch_timeout"]) as r:
            if r.status != 200:
                empty["metas"].append({"skip": "fetch_status"}); return empty
            lim = cfg["fetch_max_bytes"]
            data = r.read(lim + 1)
            if len(data) > lim:
                empty["metas"].append({"skip": "fetch_too_large"}); return empty
            ce = (r.headers.get("content-encoding") or "").lower()
            if ce == "gzip": data = gzip.decompress(data)
            elif ce == "deflate":
                try: data = zlib.decompress(data)
                except zlib.error: data = zlib.decompress(data, -zlib.MAX_WBITS)
            return handle(data, r.geturl(), r.headers.get("content-type", ""), cfg, "fetch")
    except Exception:
        empty["metas"].append({"skip": "fetch_error"}); return empty

def noop():
    return 1
'''

log = logging.getLogger("imgsniff")

# ----------------------------------------------------------------------------
# STATE
# ----------------------------------------------------------------------------
_W = None
_pool = None
_tmpdir = None
_csv_f = None
_csv_w = None
_seen_urls = set()
_loaded = set()          # URLs the browser itself fetched (crawler skips these)
_titles = OrderedDict()
_stats = Counter()
_pending = 0
_index = 0
_fetch_count = 0
_fetch_sem = None
_max_any = 0
_host_allow = _host_block = _url_block = _ref_allow = ()


def _compile(patterns):
    return tuple(re.compile(p, re.I) for p in patterns)


def _any(regexes, s):
    return any(r.search(s) for r in regexes)


def _host_ok(host: str) -> bool:
    if _host_allow and not _any(_host_allow, host):
        return False
    return not _any(_host_block, host)


def _prepare_cfg(mode="passive"):
    """Apply mode preset + derive runtime fields (also used by tests)."""
    global _max_any, _host_allow, _host_block, _url_block, _ref_allow
    if mode not in PRESETS:
        raise ValueError(f"sniff_mode must be one of {list(PRESETS)}, got {mode!r}")
    CFG.update(PRESETS[mode])
    CFG["mode"] = mode
    CFG["out_dir"] = os.path.abspath(CFG["out_dir"])
    exts = []
    for cat, on in CFG["categories"].items():
        if on:
            exts += EXTS[cat]
    if CFG["crawl_css"]:
        exts += ["css"]
    if CFG["crawl_js"]:
        exts += ["js", "mjs"]
    exts += ["webmanifest"]
    CFG["scan_exts"] = sorted(set(exts))
    _max_any = max([CFG["max_text_bytes"]] +
                   [v for c, v in CFG["max_bytes"].items() if CFG["categories"].get(c)])
    _host_allow = _compile(CFG["host_allow"])
    _host_block = _compile(CFG["host_block"])
    _url_block = _compile(CFG["url_block"])
    _ref_allow = _compile(CFG["referer_allow"])


# ----------------------------------------------------------------------------
# PIPELINE
# ----------------------------------------------------------------------------
def _hdrs(flow):
    h = flow.request.headers
    return {"ua": h.get("user-agent", "Mozilla/5.0"),
            "lang": h.get("accept-language", "en-US,en;q=0.8"),
            "cookie": h.get("cookie", ""), "cookie_host": flow.request.pretty_host}


def _record(m, page_url, depth):
    global _index
    if m.get("skip"):
        _stats["skip:" + m["skip"]] += 1
        return
    _index += 1
    p = m.get("page") or page_url or "unknown"
    _csv_w.writerow([_index, m["category"], m["path"], m["url"], m["source"], depth,
                     m["size"], m["w"], m["h"], m["fmt"], m["sha256"], p,
                     _titles.get(p, ""), datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    _csv_f.flush()
    _stats["saved"] += 1
    _stats["saved:" + m["category"]] += 1
    log.info(f"[{m['category']}] {m['path']} {m['w']}x{m['h']} {m['size']}B d{depth} <- {m['url']}")


def _schedule(urls, doc_url, depth, hdrs):
    global _fetch_count
    if not CFG["fetch_referenced"] or depth >= CFG["max_depth"]:
        return
    doc_host = urlparse(doc_url).hostname
    for u in urls:
        if _fetch_count >= CFG["max_fetches"]:
            _stats["skip:fetch_cap"] += 1
            return
        if u in _seen_urls:
            continue
        host = urlparse(u).hostname or ""
        if not _host_ok(host) or _any(_url_block, u):
            continue
        if CFG["fetch_same_site_only"] and host != doc_host:
            continue
        _seen_urls.add(u)
        _fetch_count += 1
        asyncio.ensure_future(_fetch(u, doc_url, depth + 1, hdrs))


def _consume(res, doc_url, page_url, depth, hdrs):
    if res["title"]:
        _titles[doc_url] = res["title"]
        _titles.move_to_end(doc_url)
        while len(_titles) > CFG["title_cache"]:
            _titles.popitem(last=False)
    for m in res["metas"]:
        _record(m, page_url or doc_url, depth)
    _schedule(res["urls"], doc_url, depth, hdrs)


async def _run(body, url, ctype, referer, source, depth, hdrs):
    global _pending
    try:
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(_pool, _W.handle, body, url, ctype, CFG, source)
        _consume(res, url, referer, depth, hdrs)
    except Exception as e:
        log.warning(f"task error {url}: {e}")
    finally:
        _pending -= 1


async def _fetch(url, referer, depth, hdrs):
    await asyncio.sleep(CFG["crawl_delay"])
    if url in _loaded:                      # browser got it meanwhile -> already captured
        _stats["skip:browser_loaded"] += 1
        return
    async with _fetch_sem:
        fh = {"User-Agent": hdrs["ua"], "Accept": "*/*", "Accept-Language": hdrs["lang"],
              "Accept-Encoding": "gzip, deflate", "Referer": referer}
        if hdrs["cookie"] and urlparse(url).hostname == hdrs["cookie_host"]:
            fh["Cookie"] = hdrs["cookie"]          # never sent cross-host
        try:
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(_pool, _W.fetch_handle, url, fh, CFG)
            _consume(res, url, referer, depth, hdrs)
        except Exception as e:
            log.warning(f"fetch error {url}: {e}")


def _submit(body, url, ctype, referer, source, depth, hdrs):
    global _pending
    if not body:
        return
    n = len(body)
    sn = _W.sniff(body)
    if sn:
        cat = sn[0]
        if not CFG["categories"].get(cat):
            _stats["skip:cat_" + cat] += 1
            return
        if n < CFG["min_bytes"][cat] or n > CFG["max_bytes"][cat]:
            _stats["skip:size_prefilter"] += 1
            return
        if source == "http":
            if url in _seen_urls:
                _stats["skip:duplicate_url"] += 1
                return
            _seen_urls.add(url)
    elif CFG["extract_text"] and n <= CFG["max_text_bytes"] and _W.text_kind(ctype, url):
        pass
    else:
        return
    if _pending >= CFG["max_pending"]:
        _stats["skip:backpressure"] += 1
        return
    _pending += 1
    asyncio.ensure_future(_run(body, url, ctype, referer, source, depth, hdrs))


def _complete_206(r) -> bool:
    m = re.match(r"bytes (\d+)-(\d+)/(\d+)", r.headers.get("content-range", ""))
    return bool(m) and int(m[1]) == 0 and int(m[2]) + 1 == int(m[3])


# ----------------------------------------------------------------------------
# MITMPROXY HOOKS
# ----------------------------------------------------------------------------
def request(flow: http.HTTPFlow) -> None:
    h = flow.request.headers
    if CFG["strip_conditional"]:
        for k in ("If-None-Match", "If-Modified-Since"):
            if k in h:
                del h[k]
    if CFG["strip_range"] and "Range" in h:
        ext = os.path.splitext(urlparse(flow.request.path).path)[1].lower().lstrip(".")
        if ext not in STREAM_EXTS:
            del h["Range"]
            if "If-Range" in h:
                del h["If-Range"]
    if CFG["capture_uploads"] and flow.request.method in ("POST", "PUT", "PATCH"):
        try:
            body = flow.request.content
            if not body:
                return
            ct = h.get("content-type", "")
            url = flow.request.pretty_url + "#upload"
            if "multipart" in ct.lower():
                parts = [v for _, v in flow.request.multipart_form.items(multi=True)]
                ct = ""
            else:
                parts = [body]
            for part in parts:
                _submit(part, url, ct, h.get("referer", ""), "upload", 0, _hdrs(flow))
        except Exception as e:
            log.warning(f"upload scan error: {e}")


def response(flow: http.HTTPFlow) -> None:
    r = flow.response
    if not r or flow.request.method not in CFG["methods"]:
        return
    if not (r.status_code in CFG["status_codes"] or (r.status_code == 206 and _complete_206(r))):
        return
    url = flow.request.pretty_url
    if len(_loaded) > 300_000:
        _loaded.clear()
    _loaded.add(url)
    if not _host_ok(flow.request.pretty_host) or _any(_url_block, url):
        _stats["skip:blocked"] += 1
        return
    referer = flow.request.headers.get("referer", "")
    if _ref_allow and not _any(_ref_allow, referer):
        _stats["skip:referer"] += 1
        return
    if len(r.raw_content or b"") > _max_any:
        _stats["skip:too_large_raw"] += 1
        return
    body = r.get_content(strict=False)
    _submit(body, url, r.headers.get("content-type", ""), referer, "http", 0, _hdrs(flow))


def websocket_message(flow: http.HTTPFlow) -> None:
    if not CFG["websocket"] or not flow.websocket or not flow.websocket.messages:
        return
    msg = flow.websocket.messages[-1]
    _submit(msg.content, flow.request.pretty_url + "#ws",
            "application/json" if msg.is_text else "", flow.request.pretty_url,
            "websocket", 0, _hdrs(flow))


def load(loader) -> None:
    loader.add_option("sniff_mode", str, os.environ.get("SNIFF_MODE", "passive"),
                      "Sniffer mode: passive | crawler")


def running() -> None:
    global _W, _pool, _tmpdir, _csv_f, _csv_w, _fetch_sem, _index
    _prepare_cfg(ctx.options.sniff_mode)

    _tmpdir = tempfile.mkdtemp(prefix="imgsniff_")
    with open(os.path.join(_tmpdir, "imgsniff_worker.py"), "w", encoding="utf-8") as f:
        f.write(WORKER_SRC)
    sys.path.insert(0, _tmpdir)
    import imgsniff_worker as W
    _W = W

    _pool = ProcessPoolExecutor(max_workers=CFG["workers"], mp_context=mp.get_context("spawn"))
    for _ in range(CFG["workers"]):
        _pool.submit(W.noop)
    _fetch_sem = asyncio.Semaphore(CFG["fetch_concurrency"])

    os.makedirs(CFG["out_dir"], exist_ok=True)
    path = CFG["out_csv"]
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        if rows and rows[0] == CSV_HEADER:         # resume
            for row in rows[1:]:
                if len(row) > 3 and "#" not in row[3]:
                    _seen_urls.add(row[3])
            _index = len(rows) - 1
        else:
            shutil.move(path, f"{path}.{int(time.time())}.bak")
    new = not os.path.exists(path)
    _csv_f = open(path, "a", newline="", encoding="utf-8")
    _csv_w = csv.writer(_csv_f)
    if new:
        _csv_w.writerow(CSV_HEADER)
        _csv_f.flush()
    on = [c for c, v in CFG["categories"].items() if v]
    log.info(f"Sniffer ready [{CFG['mode']}]: {CFG['workers']} workers, categories={on}, "
                 f"depth={CFG['max_depth']}, out={CFG['out_dir']}")


def done() -> None:
    log.info("Sniffer stats: " + ", ".join(f"{k}={v}" for k, v in sorted(_stats.items())))
    if _pool:
        _pool.shutdown(wait=False, cancel_futures=True)
    if _csv_f:
        _csv_f.close()
    if _tmpdir:
        shutil.rmtree(_tmpdir, ignore_errors=True)
