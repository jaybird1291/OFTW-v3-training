import os
import csv
from openai import OpenAI

PREPROCESSED_DIR = 'data_preprocessed'   # same directory
RESULTS_FILE = 'results.csv'

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("OPENAI_API_KEY environment variable not set")

client = OpenAI(api_key=api_key)

def find_single_json_in_preprocessed_dir():
    files = [f for f in os.listdir(PREPROCESSED_DIR) if f.lower().endswith('.json')]
    if not files:
        raise FileNotFoundError(f"No JSON file found in {PREPROCESSED_DIR}")
    if len(files) > 1:
        raise RuntimeError(f"Multiple JSON files found in {PREPROCESSED_DIR}, expected only one.")
    return os.path.join(PREPROCESSED_DIR, files[0])

def analyze_json(file_path: str, model: str = "o4-mini") -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        data_str = f.read()

    prompt = (
        f"""YOUR PROMPT

        Tasks:  
        1. Parse the input JSON array of EndpointSecurity (ES) events.  
        2. Identify sequences or individual events that plausibly indicate malware or post-exploitation behaviour.
        3. Give recommendations, possible artefacts to check and retrieve and a check list for a deeper investigation by a dedicated team.

        Context  
        - Event types present: exec, create, rename, unlink, tcc_modify, open, close, write, fork, exit, mount, unmount, signal, kextload, kextunload, cs_invalidated, proc_check.  
        - Typical malicious clues include:  
            - Unsigned or ad-hoc-signed binaries executed or kext-loaded.  
            - Exec / write / rename in temporary, hidden, or user-library paths (`/tmp`, `/var/folders`, `~/Library/*/LaunchAgents`, etc.).  
            - Rapid fork chains (“fork bombs”), unexpected `signal` storms, or `proc_check` failures.  
            - `tcc_modify` denying transparency-consent or privacy prompts.  
            - `mount` or `unmount` of disk images followed by `exec`.  
            - `cs_invalidated` on running code or `kextunload` immediately after `kextload`.  
            - Creation or unlinking of persistence files (LaunchAgents/Daemons, login hooks, cron, rc.plist).  
        - Treat developer tools, Apple-signed code, and items in `/Applications` as low-risk unless combined with other red flags.
        - List of typical malware behaviour / IOC to rely on:
            - Silver Sparrow style: LaunchAgent under ~/Library/Application Support/ with “agent_updater”-like name; DMG mount → exec chain; binary self-deletes.  
            - Shlayer style: “Flash Player” installer writes shell script to /private/tmp then launches via open; cleans up with unlink.  
            - XLoader style: hidden java-child process in ~/Library/Containers/... ; key-logging and clipboard read; persistence via user LaunchAgent.  
            - Adload style: ≥1 LaunchAgent **and** two LaunchDaemons, plus cron job; payload hidden in ~/Library/Application Support/<UUID>/<UUID>.  
            - MacStealer style: exfil files staged in /var/folders/*/T/* then zipped and POSTed, directory removed afterwards.  
            - TCC-bypass/ColdRoot: direct edits to TCC.db (tcc_modify) or cs_invalidated events on unsigned binaries touching privacy-protected resources.  
            - 2024 backdoors: unsigned bundle in user Library with innocuous icon; spawns reverse-shell child after 30-120 s sleep.  
            - Turtle (ransomware) pattern: burst of fork + write events (>500 files/min) followed by extension rename.  
            - LaunchAgent/LaunchDaemon persistence (MITRE T1543.001/.004): new *.plist in /Library/LaunchDaemons or ~/Library/LaunchAgents with RunAtLoad=true.  
            - Plist modification (MITRE T1647): sudden changes to Info.plist or LSEnvironment keys enabling hidden execution or dylib hijack.
        {data_str}
        """
    )

    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are an expert macOS incident-response analyst."},
            {"role": "user", "content": prompt}
        ]
    )

    return completion.choices[0].message.content.strip()

def save_result_to_csv(filename: str, analysis_result: str):
    first_line, *rest = analysis_result.splitlines()
    judgment = first_line.strip()
    explanation = " ".join([line.strip() for line in rest]) if rest else ""

    file_exists = os.path.isfile(RESULTS_FILE)
    with open(RESULTS_FILE, mode='a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(['filename', 'judgment', 'explanation'])
        writer.writerow([filename, judgment, explanation])

    print(f"Result appended to {RESULTS_FILE}")

if __name__ == "__main__":
    try:
        input_file = find_single_json_in_preprocessed_dir()
        result = analyze_json(input_file)
        print("Analysis Results:")
        print(result)
        save_result_to_csv(os.path.basename(input_file), result)
    except Exception as e:
        print(f"Error while analyzing JSON: {e}")
