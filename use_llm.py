import os
import csv
from openai import OpenAI

PREPROCESSED_DIR = os.path.join(BASE_DIR, 'data_preprocessed') # ← changed
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

def analyze_json(file_path: str, model: str = "gpt-4o") -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        data_str = f.read()

    prompt = (
        f"""YOUR PROMPT

        Here is the JSON to analyze:
        {data_str}
        """
    )

    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst specialized in macOS malware detection."},
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