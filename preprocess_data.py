#!/usr/bin/env python3
"""
preprocess_data.py

1) Find the JSON file in `preprocess_date/`.
2) Prune fields & truncate by token count.
3) Write output to `data_preprocessed/short.json`.
"""
import os
import sys
import glob
import json
import tiktoken
from tqdm import tqdm

# —— CONFIG ——————————————————————————————————————————
MAX_TOKENS      = 50000
INPUT_DIR       = os.path.join(os.path.dirname(__file__), "data/")
OUTPUT_DIR      = os.path.join(os.path.dirname(__file__), "data_preprocessed/")
OUTPUT_FILENAME = "short.json"

# —— TOKENIZER —————————————————————————————————————
def count_tokens(text: str) -> int:
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))

# —— PRUNING —————————————————————————————————————
def prune_fields(item: dict) -> dict:
    pruned = {
        "event_type": item.get("event_type"),
        "time":       item.get("time"),
    }
    proc = item.get("process", {})
    pruned["process"] = {
        "signing_id":         proc.get("signing_id"),
        "cdhash":             proc.get("cdhash"),
        "team_id":            proc.get("team_id"),
        "is_platform_binary": proc.get("is_platform_binary"),
        "executable_path":    proc.get("executable", {}).get("path"),
        "start_time":         proc.get("start_time"),
        "ppid":               proc.get("ppid"),
        "euid":               proc.get("audit_token", {}).get("euid"),
    }
    ev = item.get("event", {})
    if "create" in ev:
        pruned["event"] = {
            "create": {
                "destination_path": ev["create"]
                                         .get("destination", {})
                                         .get("existing_file", {})
                                         .get("path")
            }
        }
    elif "rename" in ev:
        pruned["event"] = {
            "rename": {
                "source_path":      ev["rename"]
                                         .get("source", {})
                                         .get("path"),
                "destination_path": ev["rename"]
                                         .get("destination", {})
                                         .get("existing_file", {})
                                         .get("path"),
            }
        }
    return pruned

# —— TRUNCATION —————————————————————————————————————
def truncate_json_by_accumulation(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise TypeError(f"Top-level JSON in {input_path} is not a list.")

    data.reverse()
    result = []
    token_total = 0

    with tqdm(total=len(data), desc="Pruning and truncating JSON") as pbar:
        for item in data:
            pruned = prune_fields(item)
            item_str = json.dumps(pruned, separators=(',', ':'))
            toks = count_tokens(item_str)
            if token_total + toks > MAX_TOKENS:
                break
            result.append(pruned)
            token_total += toks
            pbar.update(1)

    result.reverse()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, separators=(',', ':'))

    print(f"\n✔ Written {len(result)} entries ({token_total} tokens) to: {output_path}")

# —— MAIN ———————————————————————————————————————————
def main():
    # Discover JSON in INPUT_DIR
    files = glob.glob(os.path.join(INPUT_DIR, "downloaded_file.json"))
    if len(files) != 1:
        print(f"Error: Expected exactly one JSON in {INPUT_DIR}, found {len(files)}.", file=sys.stderr)
        sys.exit(1)
    input_path = files[0]

    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

    try:
        truncate_json_by_accumulation(input_path, output_path)
    except Exception as e:
        print(f"✖ Error during processing: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()