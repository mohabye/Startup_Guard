# Startup Folder Monitor

This script monitors the Windows startup folder for new files and sends an alert via Telegram if a file is detected with a suspicious extension or if it is identified as malicious or unknown by VirusTotal. 

## Features

- **File Monitoring**: Continuously monitors the Windows startup folder for new files.
- **VirusTotal Integration**: Checks file hashes against VirusTotal to determine if they are malicious or unknown.
- **Suspicious File Detection**: Flags files with extensions `.py`, `.bat`, `.sh`, and `.cpp` as suspicious.
- **Telegram Alerts**: Sends detailed alerts to a specified Telegram chat.

## Requirements

- Python 3.x
- `requests` library
- `psutil` library

## Setup

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/yourusername/startup-folder-monitor.git
    cd startup-folder-monitor
    ```

2. **Install Dependencies**:
    ```sh
    pip install requests psutil
    ```

3. **Configure the Script**:
    - Replace the following placeholders in the script with your actual values:
        ```python
        API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
        STARTUP_FOLDER = 'C:\\Users\\YOUR_USERNAME\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
        TELEGRAM_CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'
        ```

## Usage

1. **Run the Script**:
    ```sh
    python startup_folder_monitor.py
    ```

2. **Monitor Alerts**:
    - The script will continuously check the startup folder every 10 seconds.
    - If a new file is detected, its hash will be checked against VirusTotal.
    - If the file is detected as malicious, unknown, or has a suspicious extension, an alert will be sent to the specified Telegram chat.

## Script Details

The script performs the following actions:

1. **Hash Calculation**: Computes the MD5 hash of new files in the startup folder.
2. **VirusTotal Check**: Queries VirusTotal with the file hash to get its reputation.
3. **Suspicious Extension Check**: Flags files with extensions `.py`, `.bat`, `.sh`, and `.cpp` as suspicious.
4. **Parent Process Information**: Gathers information about the parent process of the script for inclusion in the alert.
5. **Telegram Alert**: Sends a detailed alert message to the specified Telegram chat with the following details:
    - Alert Type: Malicious File, Unknown File, or Suspicious File
    - File Name
    - File Path
    - File Hash
    - VirusTotal Reputation
    - Parent Process Name
    - Parent Process PID
    - Parent Process Path
    - Parent Process Hash

### Example Alert

![image](https://github.com/mohabye/Startup_Guard/assets/76062472/d5defa88-9602-436c-b672-b6101fee511f)
