import os
import hashlib
import requests
import psutil
import time

API_KEY = '6721398630d0d3deca1d1516fc3a56428f8eea1425386eeb90fd4a9ffe9dcb6b'
STARTUP_FOLDER = 'C:\\Users\\ESCANOR\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
TELEGRAM_BOT_TOKEN = '7014754743:AAFoqAOilXuX7ZB25z8WGKtKuXkhhyBCezs'
TELEGRAM_CHAT_ID = '1399842880'
checked_files = set()
SUSPICIOUS_EXTENSIONS = {'.py', '.bat', '.sh', '.cpp'}

def get_file_hash(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

def check_virustotal(file_hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={file_hash}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"VirusTotal API request failed with status code {response.status_code}: {response.text}")
    except Exception as e:
        print(f"Exception occurred while checking VirusTotal: {e}")
    return None

def send_alert_to_telegram(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message
    }
    try:
        response = requests.post(url, data=data)
        if response.status_code != 200:
            print(f"Failed to send message to Telegram: {response.text}")
        else:
            print("Alert sent to Telegram successfully.")
    except Exception as e:
        print(f"Exception occurred while sending alert to Telegram: {e}")

def show_alert(file_name, file_path, file_hash, vt_reputation, parent_proc_name, parent_proc_pid, parent_proc_path, parent_proc_hash, alert_type="Malicious File"):
    message = (
        f"Alert Type: {alert_type}\n"
        "-----------------------\n"
        f"File Name: {file_name}\n"
        "-----------------------\n"
        f"File Path: {file_path}\n"
        "-----------------------\n"
        f"File Hash: {file_hash}\n"
        "-----------------------\n"
        f"VirusTotal Reputation: {vt_reputation}\n"
        "-----------------------\n"
        f"Parent Process Name: {parent_proc_name}\n"
        "-----------------------\n"
        f"Parent Process PID: {parent_proc_pid}\n"
        "-----------------------\n"
        f"Parent Process Path: {parent_proc_path}\n"
        "-----------------------\n"
        f"Parent Process Hash: {parent_proc_hash}\n"
    )
    
    send_alert_to_telegram(message)

def check_startup_folder():
    global checked_files
    print("Checking startup folder...")
    for file_name in os.listdir(STARTUP_FOLDER):
        file_path = os.path.join(STARTUP_FOLDER, file_name)
        file_extension = os.path.splitext(file_name)[1].lower()
        print(f"Checking file: {file_path}")

        if file_path not in checked_files:
            print(f"New file detected: {file_name}")
            checked_files.add(file_path)
            file_hash = get_file_hash(file_path)

            if file_hash:
                vt_result = check_virustotal(file_hash)
                is_suspicious_extension = file_extension in SUSPICIOUS_EXTENSIONS
                
                if vt_result is not None:
                    positives = vt_result.get('positives', 0)
                    total = vt_result.get('total', 0)
                    
                    if positives > 0 or vt_result.get('response_code') == 0 or is_suspicious_extension:
                        parent_process = psutil.Process(os.getpid()).parent()
                        parent_proc_name = parent_process.name()
                        parent_proc_pid = parent_process.pid
                        parent_proc_path = parent_process.exe()
                        parent_proc_hash = get_file_hash(parent_proc_path)
                        
                        if positives > 0:
                            vt_reputation = f"Detected by {positives} out of {total} scanners"
                            alert_type = "Malicious File"
                        elif vt_result.get('response_code') == 0:
                            vt_reputation = "Unknown file"
                            alert_type = "Unknown File"
                        else:
                            vt_reputation = "Suspicious extension"
                            alert_type = "Suspicious File"

                        show_alert(file_name, file_path, file_hash, vt_reputation, parent_proc_name, parent_proc_pid, parent_proc_path, parent_proc_hash, alert_type)
                    else:
                        print(f"File {file_name} is not detected as malicious.")
                else:
                    if is_suspicious_extension:
                        parent_process = psutil.Process(os.getpid()).parent()
                        parent_proc_name = parent_process.name()
                        parent_proc_pid = parent_process.pid
                        parent_proc_path = parent_process.exe()
                        parent_proc_hash = get_file_hash(parent_proc_path)
                        
                        vt_reputation = "Suspicious extension"
                        alert_type = "Suspicious File"

                        show_alert(file_name, file_path, file_hash, vt_reputation, parent_proc_name, parent_proc_pid, parent_proc_path, parent_proc_hash, alert_type)
                    else:
                        print(f"Error checking VirusTotal for {file_name}")
            else:
                print(f"Error hashing file {file_name}")
        else:
            print(f"File {file_name} is already checked.")

if __name__ == "__main__":
    while True:
        check_startup_folder()
        time.sleep(10)
