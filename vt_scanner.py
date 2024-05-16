import os
import requests
import time

VIRUSTOTAL_API_KEY = 'eb84c73c89bdef6ad272f7f93ba39b2bdf4534977f0babf43ae912d224bc4aa1'  

def is_hidden(filepath):
    return os.path.basename(filepath).startswith('.')

def upload_file_to_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f"Error uploading file {file_path}: {response.status_code}")
        return None

def get_analysis_report(file_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis_result = response.json()
            if analysis_result['data']['attributes']['status'] == 'completed':
                return analysis_result
            else:
                time.sleep(10)  # Wait for 10 seconds before checking again
        else:
            print(f"Error retrieving analysis report: {response.status_code}")
            return None

def scan_file(file_path):
    file_id = upload_file_to_virustotal(file_path)
    if file_id:
        return get_analysis_report(file_id)
    return None

def scan_directory(directory):
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if not is_hidden(file_path):  # Scan only non-hidden files
                print(f"Scanning {file_path}...")
                report = scan_file(file_path)
                if report:
                    results[file_path] = report
    return results

def main():
    target_directory = 'samples'  # Directory to scan

    results = scan_directory(target_directory)

    for file_path, report in results.items():
        print(f"File: {file_path}")
        if 'attributes' in report['data']:
            for engine, result in report['data']['attributes']['results'].items():
                print(f"  Engine: {engine}")
                print(f"  Category: {result['category']}")
                print(f"  Result: {result['result']}")
                print(f"  Method: {result['method']}")
                print(f"  Engine Version: {result['engine_version']}")
                print(f"  Engine Update: {result['engine_update']}")

if __name__ == "__main__":
    main()
