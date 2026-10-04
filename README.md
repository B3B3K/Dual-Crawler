## Overview

Webs sniffer that uses mitmproxy library to intercept HTTP/HTTPS traffic and extract metadata from on-going traffic, particularly visuals. The tool can recursively fetch linked resources within the same domain and save the extracted data to a CSV file.

## Features

1. **URL Filtering**: Intercept URLs based on specified patterns.
2. **Content Type Handling**: Extract metadata from various content types (e.g., images, videos).
3. **Recursive Fetching**: Recursively fetch linked resources within the same domain.
4. **Output**: Save extracted data to a CSV file with detailed metadata.
5. **Configuration**: Customize behavior via a configuration dictionary (`CFG`).

## Usage

### Installation

   ```sh
   pipx install -r requirements.txt
   ```

### Running the Sniffer

To start the sniffer, run the following command:

```sh
mitmdump -s sniffer.py
```

### Configuration

The tool can be configured via a `CFG` before runtime. Configuration options include:

- `out_dir`: Output directory for the CSV file.
- `categories`: Categories of content to extract (e.g., images, videos).
- `max_depth`: Maximum depth of recursive fetching.
- `fetch_referenced`: Whether to recursively fetch referenced resources.
- `fetch_concurrency`: Maximum number of concurrent fetches.

## Example Configuration

```python
CFG = {
    "out_dir": "./output",
    "categories": {"images": True, "videos": False},
    "max_depth": 2,
    "fetch_referenced": True,
    "fetch_concurrency": 5,
}
```
