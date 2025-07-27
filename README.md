# OFTW v3.0 - Training "How to Use LLMs to Detect macOS Malware" by Martina Tivadar

> Here you'll find Martina Tivadar's training slides and labs, along with the scripts to automate malware detection on macOS using the OpenAI o4‑mini model with GitHub actions as part of the last lab.


## Table of Contents

1. [Overview](#overview)  
2. [Repository Structure](#repository-structure)  
3. [Prerequisites](#prerequisites)  
4. [How to use](#how-to-use)  


## Overview

[Martina Tivadar](https://www.linkedin.com/in/martina-tivadar), research assistant at iVerify showed us how large-language models (LLMs) can help in macOS malware detection.

We used Python, Apple's Endpoint Security framework and local running LLMs with LM Studio / OpenAI's API to detect macOS malware.

If you're interested to learn more about #OFTW from Objective-See foundation and the training check my blog post: https://jaybird1291.github.io/blog-cyber/en/posts/oftw-v3 

## Repository Structure

```text
OFTW-v3-training/
├── .github/
│   └── workflows/
│       └── main.yml           # CI: Fetch → Preprocess → Analyze → Commit results
├── data/                      # Raw EndpointSecurity JSON logs (empty - used in the GitHub Action)
├── data_preprocessed/         # Truncated & pruned logs (empty - used in the GitHub Action)
├── fetch_data.py              # Download raw ES logs from Google Drive
├── preprocess_data.py         # Prune fields & limit token context
├── use_llm.py                 # Send JSON to LLM and parse response
├── results.csv                # Latest analysis output (malware detection results)
└── README.md                  # (you are here)
```

## Prerequisites
- macOS 12+
- Python 3 (and pip)
- LM Studio (local LLMs) or an OpenAI API key
- GitHub repo with actions enabled (for CI/CD automation)

## How to use
You can either follow the slides & labs or just fork this repo and: 
1. Open your repository
2. Go to Settings
3. In the sidebar, click "Secrets and variables" and then "Actions"
4. Click "New repository secret"
5. Name the secret ``OPENAI_API_KEY`` and paste your token as the value (like ``sk-proj-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxx``).
6. Click "Add secret" to save

To use another JSON file, create your own Google Drive repository, upload your file and then edit the ``FILE_ID`` in [fetch_data.py](https://github.com/jaybird1291/OFTW-v3-training/blob/90bbf13e374910e4afc126acea3947c620a0c177/fetch_data.py#L11C1-L12C1) with your own.
