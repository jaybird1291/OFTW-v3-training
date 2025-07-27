#!/usr/bin/env python3
"""
preprocess_data.py

1) Download a public JSON file from Google Drive.
2) Find that JSON in `preprocess_date/`.
3) Prune fields & truncate by token count.
4) Emit `data_preprocessed/short.json` for downstream steps.
"""
import os
import sys
import glob
import json
import requests
import tiktoken
from tqdm import tqdm

# —— CONFIG ———————————————————————————————————————
FILE_ID        = "1HmIIxX-KrX-o6JWuRnwE2iTh-SsUBZco"
INPUT_DIR      = os.path.join(os.path.dirname(__file__), "preprocess_date")
OUTPUT_DIR     = os.path.join(os.path.dirname(__file__), "data_preprocessed")
OUTPUT_FILE    = "short.json"
MAX_TOKENS     = 190000
CHUNK_SIZE     = 32768

# —— GOOGLE DRIVE DOWNLOAD ——————————————————————————
def get_confirm_token(resp: requests.Response) -> str:
    for k, v in resp.cookies.items():
        if k.startswith("download_warning"):
            return v
    return None

def save_stream(resp: requests.Response, dst: str):
    os.makedirs(os.path.dirname(dst), exist_ok=True)  # ensure folder exists  [oai_citation:6‡Nkmk Note](https://note.nkmk.me/en/python-os-mkdir-makedirs/?utm_source=chatgpt.com)
    with open(dst, "wb") as f:
        for chunk in resp.iter_content(CHUNK_SIZE):
            if chunk:
                f.write(chunk)

def download_from_gdrive(file_id: str, dst: str):
    """Download a file from Google Drive, handling large-file tokens."""
    URL = "https://docs.google.com/uc?export=download"
    sess = requests.Session()
    r = sess.get(URL, params={"id": file_id}, stream=True)
    token = get_confirm_token(r)
    if token:
        r = sess.get(URL, params={"id": file_id, "confirm": token}, stream=True)
    save_stream(r, dst)
    print(f"✔ Downloaded JSON to: {dst}")  # requests + streaming  [oai_citation:7‡docsaid.org](https://docsaid.org/en/blog/download-from-google-drive-using-python/?utm_source=chatgpt.com)

# —— TOKEN COUNTING & PRUNING ———————————————————————
def count_tokens(text: str) -> int:
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))  # tiktoken usage  [oai_citation:8‡cookbook.openai.com](https://cookbook.openai.com/examples/how_to_count_tokens_with_tiktoken?utm_source=chatgpt.com)

def prune_fields(item: dict) -> dict:
    """Return only the fields that are valuable for malware analysis."""

    proc = item.get("process", {})
    pr = {
        "event_type": item.get("event_type"),
        "time":       item.get("time"),

        # ---------- process ----------
        "process": {
            "pid":                proc.get("pid"),
            "ppid":               proc.get("ppid"),
            "start_time":         proc.get("start_time"),
            "argv":               proc.get("arguments"),       # full command‑line
            "executable_path":    proc.get("executable", {}).get("path"),
            "uid":                proc.get("audit_token", {}).get("uid"),
            "euid":               proc.get("audit_token", {}).get("euid"),
            "gid":                proc.get("audit_token", {}).get("gid"),
            "signing_id":         proc.get("signing_id"),
            "cdhash":             proc.get("cdhash"),
            "team_id":            proc.get("team_id"),
            "is_platform_binary": proc.get("is_platform_binary"),
            "image_uuid":         proc.get("image_uuid"),
        },
    }

    # ---------- file / fs events ----------
    ev = item.get("event", {})
    if "create" in ev:
        dst = ev["create"].get("destination", {}).get("existing_file", {})
        pr["event"] = {
            "create": {
                "destination_path": dst.get("path"),
                "inode":            dst.get("inode"),
                "mode":             dst.get("mode"),
                "uid":              dst.get("uid"),
                "gid":              dst.get("gid"),
            }
        }
    elif "rename" in ev:
        src = ev["rename"].get("source", {})
        dst = ev["rename"].get("destination", {}).get("existing_file", {})
        pr["event"] = {
            "rename": {
                "source_path":      src.get("path"),
                "destination_path": dst.get("path"),
                "inode":            dst.get("inode"),
                "mode":             dst.get("mode"),
                "uid":              dst.get("uid"),
                "gid":              dst.get("gid"),
            }
        }
    elif "exec" in ev:          # keep exec details too
        ex = ev["exec"].get("process", {})
        pr["event"] = {
            "exec": {
                "target_path":      ex.get("executable", {}).get("path"),
                "argv":             ex.get("arguments"),
                "cs_flags":         ex.get("cs_flags"),
                "signer_type":      ex.get("signer_type"),
            }
        }

    return pr

def truncate_json(input_path: str, output_path: str):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise TypeError(f"Top-level JSON in {input_path} is not a list.")
    data.reverse()

    kept, total_tokens = [], 0
    with tqdm(total=len(data), desc="Truncating…") as pbar:  # tqdm usage  [oai_citation:9‡GitHub](https://github.com/tqdm/tqdm?utm_source=chatgpt.com)
        for itm in data:
            pr = prune_fields(itm)
            s  = json.dumps(pr, separators=(",", ":"))
            tks = count_tokens(s)
            if total_tokens + tks > MAX_TOKENS:
                break
            kept.append(pr)
            total_tokens += tks
            pbar.update(1)

    kept.reverse()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)  # ensure folder  [oai_citation:10‡Nkmk Note](https://note.nkmk.me/en/python-os-mkdir-makedirs/?utm_source=chatgpt.com)
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(kept, out, separators=(",", ":"))

    print(f"\n✔ Wrote {len(kept)} entries ({total_tokens} tokens) to {output_path}")

# —— MAIN ————————————————————————————————————————
def main():
    # 1) Download raw JSON
    os.makedirs(INPUT_DIR, exist_ok=True)  # create if missing  [oai_citation:11‡Nkmk Note](https://note.nkmk.me/en/python-os-mkdir-makedirs/?utm_source=chatgpt.com)
    raw_path = os.path.join(INPUT_DIR, "raw.json")
    download_from_gdrive(FILE_ID, raw_path)

    # 2) Locate the downloaded JSON dynamically
    files = glob.glob(os.path.join(INPUT_DIR, "*.json"))  # find JSON  [oai_citation:12‡Nkmk Note](https://note.nkmk.me/en/python-glob-usage/?utm_source=chatgpt.com)
    if len(files) != 1:
        print(f"Error: expected exactly one JSON in {INPUT_DIR}, found {len(files)}", file=sys.stderr)
        sys.exit(1)
    input_path = files[0]

    # 3) Prune & truncate → data_preprocessed/short.json
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)
    try:
        truncate_json(input_path, output_path)
    except Exception as e:
        print(f"✖ Error during processing: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
