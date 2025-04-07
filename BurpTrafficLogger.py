# -*- coding: utf-8 -*-

from burp import IBurpExtender, IHttpListener
from java.io import File
import json
import threading
import time

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request/Response Logger with Timestamp")
        callbacks.registerHttpListener(self)

        # 🔧 CHANGE THIS TO A VALID PATH ON YOUR SYSTEM
        self._log_file_path = "C:/Users/wardell/Desktop/Hacking/BurpExtension/burp_http_log.json"

        self._entry_counter = 0
        self._lock = threading.Lock()

        self._ensure_log_file_exists()
        print("[*] Logger loaded. Capturing ALL traffic with timestamps.")
        print("[*] Log file path:", self._log_file_path)

    def _ensure_log_file_exists(self):
        try:
            log_file = File(self._log_file_path)
            if not log_file.exists():
                with open(self._log_file_path, "w") as f:
                    json.dump([], f)
        except Exception as e:
            print("[!] Error creating log file:", e)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        with self._lock:
            try:
                content = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
                if content is None:
                    return

                content_str = self._helpers.bytesToString(content)
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                self._entry_counter += 1
                entry = {
                    "entry_number": self._entry_counter,
                    "type": "request" if messageIsRequest else "response",
                    "timestamp": timestamp,
                    "content": content_str
                }

                print("[*] Captured {} #{} at {}".format(entry["type"], self._entry_counter, timestamp))
                self._write_log_entry(entry)
            except Exception as e:
                print("[!] Error processing message:", e)

    def _write_log_entry(self, entry):
        try:
            with open(self._log_file_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            print("[!] Could not read log file:", e)
            data = []

        data.append(entry)

        try:
            with open(self._log_file_path, "w") as f:
                json.dump(data, f, indent=2)
            print("[*] Logged entry #{} to file".format(entry["entry_number"]))
        except Exception as e:
            print("[!] Could not write to log file:", e)
