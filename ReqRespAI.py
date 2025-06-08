
####################################################################################
## Copyright (c) 2025 Red7en, LLC                                                 ##
##                                                                                ## 
## Permission is hereby granted, free of charge, to any person obtaining a copy   ##
## of this software and associated documentation files (the "Software"), to deal  ##
## in the Software without restriction, including without limitation the rights   ##
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      ##
## copies of the Software, and to permit persons to whom the Software is          ##
## furnished to do so, subject to the following conditions:                       ##
##                                                                                ##
## The above copyright notice and this permission notice shall be included in all ##
## copies or substantial portions of the Software.                                ##
##                                                                                ##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     ##   
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       ##
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    ##
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         ##
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  ##
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  ##
## SOFTWARE.                                                                      ##
####################################################################################


import os
import json
import subprocess
import time
import csv

# Load configuration from config.txt
def load_config():
    config = {}
    with open("config.txt") as f:
        for line in f:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                config[key] = value.strip()
    return config

# Load config
config = load_config()
LLM_MODEL = config.get("LLM_MODEL", "deepseek-coder")
MAX_INPUT_SIZE = int(config.get("MAX_INPUT_SIZE", 2000))
BASE_LLM_TIMEOUT = int(config.get("BASE_LLM_TIMEOUT", 30))
HARD_TIMEOUT = int(config.get("HARD_TIMEOUT", 60))
MAX_RETRIES = int(config.get("MAX_RETRIES", 2))
RESTART_FREQUENCY = int(config.get("RESTART_FREQUENCY", 5))
PROXY_FILE = config.get("PROXY_FILE", "proxy_traffic.json")
LLM_OUTPUT_FILE = config.get("LLM_OUTPUT_FILE", "LLM.txt")
ERROR_LOG_FILE = config.get("ERROR_LOG_FILE", "errors.txt")
REJECTED_ENTRIES_FILE = config.get("REJECTED_ENTRIES_FILE", "rejected_entries.json")
CSV_SUMMARY_FILE = "vulnerability_summary.csv"

# Stats
total_requests = 0
total_timeouts = 0

def restart_ollama():
    print("🔄 Restarting Ollama...")
    subprocess.run(["ollama", "stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)

def log_error(entry_index, request_data, error_message):
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n### ERROR ON ENTRY {entry_index} ###\n")
        f.write(f"[ERROR MESSAGE]: {error_message}\n")
        f.write(f"[REQUEST DATA]:\n{request_data}\n")
        f.write("="*80 + "\n")

    rejected_entry = {
        "entry_index": entry_index,
        "error_message": error_message,
        "request_data": request_data
    }

    if os.path.exists(REJECTED_ENTRIES_FILE):
        with open(REJECTED_ENTRIES_FILE, "r", encoding="utf-8") as f:
            try:
                rejected_data = json.load(f)
            except json.JSONDecodeError:
                rejected_data = []
    else:
        rejected_data = []

    rejected_data.append(rejected_entry)

    with open(REJECTED_ENTRIES_FILE, "w", encoding="utf-8") as f:
        json.dump(rejected_data, f, indent=4)

def write_to_csv(entry_number, entry_type, summary, score, vector, exploit):
    file_exists = os.path.exists(CSV_SUMMARY_FILE)
    with open(CSV_SUMMARY_FILE, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["Entry #", "Type", "Summary", "CVSS Score", "CVSS Vector", "Possible Exploit"])
        writer.writerow([entry_number, entry_type, summary, score, vector, exploit])

def extract_between(text, start_marker, end_marker):
    try:
        return text.split(start_marker)[1].split(end_marker)[0].strip()
    except (IndexError, AttributeError):
        return "N/A"

def extract_cvss_info(text):
    try:
        section = text.split("[CVSS SCORE]")[-1].strip()
        lines = section.splitlines()
        score_line = lines[0].strip() if lines else "N/A"
        vector_line = next((l.strip() for l in lines if l.strip().startswith("CVSS:")), "N/A")
        return score_line, vector_line
    except Exception:
        return "N/A", "N/A"

def analyze_with_llm(request_response, entry_index):
    global total_requests, total_timeouts

    if len(request_response) > MAX_INPUT_SIZE:
        request_response = request_response[:MAX_INPUT_SIZE] + "\n\n[TRIMMED DUE TO SIZE]\n"

    prompt = f"""Analyze the following HTTP request and response for OWASP Top 10 vulnerabilities.

Return your findings in this format:

[SUMMARY]
A brief description of the issue.

[POSSIBLE EXPLOIT]
How the vulnerability could be exploited.

[CVSS SCORE]
<score> - explanation
CVSS:3.1/... (CVSS vector)

--- Begin Analysis ---

{request_response}"""

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"  🔍 Entry {entry_index} (Attempt {attempt}/{MAX_RETRIES})... ", end="", flush=True)

            process = subprocess.Popen(
                ["ollama", "run", LLM_MODEL],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )

            stdout, stderr = process.communicate(input=prompt, timeout=HARD_TIMEOUT)

            if process.returncode != 0:
                raise Exception(stderr)

            print("✅ Done")
            total_requests += 1
            return request_response, stdout.strip()

        except subprocess.TimeoutExpired:
            print("⏳ Timeout! Killing and retrying...")
            process.kill()
            if attempt == MAX_RETRIES:
                total_timeouts += 1
                log_error(entry_index, request_response, "Final timeout exceeded")
        except Exception as e:
            print(f"❌ Error: {e}")
            if attempt == MAX_RETRIES:
                restart_ollama()
                log_error(entry_index, request_response, str(e))
                return request_response, "[ERROR] Skipped due to repeated failure."

    return request_response, "[ERROR] Skipped after retries."

def process_proxy_logs():
    global total_requests, total_timeouts

    print("🔐 Welcome to the AI Web Vulnerability Scanner!")
    print("This tool analyzes HTTP requests and responses using a local LLM.")
    print("It identifies OWASP Top 10 vulnerabilities and generates reports.\n")

    print("🛠️  Configuration Values Loaded from config.txt:")
    for key, value in config.items():
        print(f"  - {key}: {value}")
    print("\n")

    try:
        with open(PROXY_FILE, "r", encoding="utf-8") as f:
            traffic_data = json.load(f)
    except Exception as e:
        print(f"❌ Failed to read {PROXY_FILE}: {e}")
        return

    total_entries = len(traffic_data)
    print(f"📊 Found {total_entries} entries in {PROXY_FILE}.")

    try:
        start_index = int(input(f"▶️ Enter number of entries to skip (0-{total_entries}): ").strip())
        if start_index < 0 or start_index >= total_entries:
            print("❌ Invalid number. Starting from 0.")
            start_index = 0
    except ValueError:
        print("❌ Invalid input. Starting from 0.")
        start_index = 0

    write_mode = "w" if start_index == 0 else "a"

    if write_mode == "w":
        open(LLM_OUTPUT_FILE, "w").close()
        open(ERROR_LOG_FILE, "w").close()
        open(REJECTED_ENTRIES_FILE, "w").close()
        open(CSV_SUMMARY_FILE, "w").close()

    print(f"⏩ Starting from entry {start_index + 1}...")
    print(f"📂 Output mode: {'OVERWRITE' if write_mode == 'w' else 'APPEND'}")

    for i, entry in enumerate(traffic_data[start_index:], start=start_index + 1):
        entry_type = entry.get("type", "unknown")
        content = entry.get("content", "")
        if not content:
            continue

        print(f"🔄 Processing {entry_type.upper()} ({i}/{total_entries})")
        analyzed_request, llm_output = analyze_with_llm(content, i)

        result = f"""\n#########################################
### {entry_type.upper()} ANALYSIS (Entry {i}) ###
#########################################

[REQUEST/RESPONSE]
-----------------------------------
{analyzed_request}

[LLM ANALYSIS]
-----------------------------------
{llm_output}
"""

        with open(LLM_OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(result)

        if "[ERROR]" not in llm_output:
            summary = extract_between(llm_output, "[SUMMARY]", "[POSSIBLE EXPLOIT]")
            exploit = extract_between(llm_output, "[POSSIBLE EXPLOIT]", "[CVSS SCORE]")
            score, vector = extract_cvss_info(llm_output)
            write_to_csv(i, entry_type.upper(), summary, score, vector, exploit)

        if i % RESTART_FREQUENCY == 0:
            restart_ollama()

    processed = total_requests + total_timeouts
    success_rate = (total_requests / processed * 100) if processed else 0

    print("\n📊 DONE")
    print(f"✅ Successful Requests: {total_requests}")
    print(f"⏳ Timed-Out Requests (Final Retries Only): {total_timeouts}")
    print(f"📈 Success Rate: {success_rate:.2f}%")
    print(f"📝 Output saved to: {LLM_OUTPUT_FILE}")

if __name__ == "__main__":
    process_proxy_logs()
