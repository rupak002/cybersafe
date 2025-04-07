import hashlib
import os
import requests
import pandas as pd
import time

# Function to calculate SHA-256 hash of the file
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to check hash against hash.csv
def check_hash_in_csv(hash_value, csv_file="hash.csv"):
    df = pd.read_csv(csv_file)
    df.columns = df.columns.str.strip()  # Remove any extra spaces in column names
    print("CSV Columns:", df.columns)  # Print column names for debugging
    if 'hash' in df.columns and 'message' in df.columns:
        if hash_value in df['hash'].values:
            message = df.loc[df['hash'] == hash_value, 'message'].values[0]
            return True, message
    return False, None

# Function to send file to VirusTotal
def send_to_virustotal(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
    params = {'apikey': api_key}
    
    response = requests.post(url, files=files, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Could not connect to VirusTotal'}

# Function to get VirusTotal scan report
def get_virustotal_report(scan_id, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': api_key,
        'resource': scan_id
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': 'Could not retrieve VirusTotal report'}

# Function to check VirusTotal scan status
def check_virustotal_scan_status(scan_id, api_key):
    print("Waiting for VirusTotal scan results...")
    while True:
        report = get_virustotal_report(scan_id, api_key)
        if 'response_code' in report and report['response_code'] == 1:
            if report['positives'] > 0:
                print("File is flagged as malicious by the following engines:")
                for engine, result in report['scans'].items():
                    if result['detected']:
                        print(f"- {engine}: {result['result']}")
            else:
                print("File is clean. No malicious detections found.")
            break
        elif 'error' in report:
            print("Error:", report['error'])
            break
        else:
            print("Scan results not ready yet. Checking again in 30 seconds...")
            time.sleep(30)

# Main script
if __name__ == "__main__":
    file_path = input("Enter Your File Name: ")  # File you want to check
    csv_file = "virushashes"  # csv file containing known hashes
    api_key = "8d45b62b6fd3d5226cc716c37cb2fbda6e0fcc44c5d8561ca33e889c8badf533"  # VirusTotal API key

    # Step 1: Calculate file hash
    file_hash = calculate_file_hash(file_path)
    print(f"Generated Hash (SHA-256) for {file_path}: {file_hash}")

    # Step 2: Check hash in CSV
    found, message = check_hash_in_csv(file_hash, csv_file)

    if found:
        print(f"Hash found in database. Message: {message}")
    else:
        print("Hash not found. Sending file to VirusTotal...")
        
        # Step 3: Send to VirusTotal if not found
        vt_response = send_to_virustotal(file_path, api_key)
        if 'scan_id' in vt_response:
            scan_id = vt_response['scan_id']
            check_virustotal_scan_status(scan_id, api_key)
        else:
            print("Error sending file to VirusTotal:", vt_response.get('error', 'Unknown error'))
