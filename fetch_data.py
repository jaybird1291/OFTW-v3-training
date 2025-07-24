#!/usr/bin/env python3
"""
preprocess_data.py

Automatically download a public Google Drive file into a specified directory.
Designed to run in CI/CD pipelines (e.g., GitHub Actions).
"""
import os
import requests

FILE_ID = "1HmIIxX-KrX-o6JWuRnwE2iTh-SsUBZco"
DEST_DIR = os.path.join(os.path.dirname(__file__), "data/")
DEST_FILENAME = "downloaded_file.json"
CHUNK_SIZE = 32768


def get_confirm_token(response):
    """
    Extract confirmation token from cookies for large file downloads.
    """
    for key, value in response.cookies.items():
        if key.startswith("download_warning"):
            return value
    return None


def save_response_content(response, destination_path):
    """
    Stream the response content to the destination file path in chunks.
    """
    with open(destination_path, "wb") as f:
        for chunk in response.iter_content(CHUNK_SIZE):
            if chunk:
                f.write(chunk)


def download_from_google_drive(file_id, destination_path):
    """
    Download a file from Google Drive using its file ID.
    Handles confirmation for large files.
    """
    URL = "https://docs.google.com/uc?export=download"
    session = requests.Session()

    # Initial request
    response = session.get(URL, params={"id": file_id}, stream=True)
    token = get_confirm_token(response)

    # If we have a confirmation token, re-request with it
    if token:
        response = session.get(URL, params={"id": file_id, "confirm": token}, stream=True)

    # Save content to disk
    save_response_content(response, destination_path)
    print(f"Downloaded Google Drive file to: {destination_path}")


def main():
    # Ensure destination directory exists
    os.makedirs(DEST_DIR, exist_ok=True)
    dest_path = os.path.join(DEST_DIR, DEST_FILENAME)

    download_from_google_drive(FILE_ID, dest_path)


if __name__ == "__main__":
    main()
