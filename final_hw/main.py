# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import requests
from config import API_KEY, API_FILE_URL, API_FILE_ANALYSES_URL


file_path = "invoice-42369643.xlsm"
headers = {"accept": "application/json", "x-apikey": API_KEY}
payload = {"file": "/home/evgeny/hse/python/final_hw/invoice-42369643.xlsm"}

# Step 1. Unzip file

# Step 2. Upload file on VirusTotal server
with open(file_path, "rb") as file:
    files = {"file": (file_path, file)}
    response = requests.post(API_FILE_URL, headers=headers, files=files)
    _id = response.json()["data"]["id"]

# Step 3. Analyze file on malware
url = "{}/{}".format(API_FILE_ANALYSES_URL, _id)
response = requests.get(url, headers=headers)
report = response.json()

# print(report["data"]["attributes"]["results"])

url_behaviors = "{}/{}/behaviours".format(API_FILE_URL, _id)
print(url_behaviors)
# response = requests.get(url_behaviors, headers=headers)
# print(response.text)
