import pyperclip
import requests
import time
import urllib3

# Replace with your own VirusTotal API key
API_KEY = 'Your_API_Key'

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to scan a URL with VirusTotal
def scan_url(url):
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {
        'apikey': API_KEY,
        'resource': url
    }

    # Disable SSL verification for the GET request
    response = requests.get(api_url, params=params, verify=False)

    if response.status_code == 200:
        json_response = response.json()

        if json_response.get('response_code') == 1:
            scan_results = json_response.get('positives', 0)
            if scan_results > 0:
                print(f'The URL {url} is potentially malicious. Performing file scan...')
                file_scan(url)
            else:
                print(f'The URL {url} is safe.')
        else:
            print(f'The URL {url} has not been scanned on VirusTotal.')
    else:
        print(f'Error {response.status_code}: Failed to scan URL.')

# Function to perform file scan on a URL
def file_scan(url):
    api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {
        'apikey': API_KEY
    }

    # Retrieve the file associated with the URL
    file_response = requests.get(url, verify=False)

    if file_response.status_code == 200:
        # Upload the file for scanning
        files = {'file': file_response.content}
        response = requests.post(api_url, files=files, params=params, verify=False)

        if response.status_code == 200:
            file_scan_response = response.json()
            resource = file_scan_response.get('resource')

            # Check the scan results after uploading the file
            check_file_scan(resource)
        else:
            print(f'Error {response.status_code}: Failed to upload file for scanning.')
    else:
        print(f'Error {file_response.status_code}: Failed to retrieve file associated with URL.')

# Function to check the file scan report
def check_file_scan(resource):
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {
        'apikey': API_KEY,
        'resource': resource
    }

    # Disable SSL verification for the GET request
    response = requests.get(api_url, params=params, verify=False)

    if response.status_code == 200:
        file_report = response.json()
        if 'response_code' in file_report:
            response_code = file_report['response_code']
            if response_code == 0:
                print('File not found in VirusTotal database.')
            elif response_code == 1:
                scan_results = file_report.get('positives', 0)
                if scan_results > 0:
                    print(f'Malware detected in the file (positives: {scan_results}).')
                else:
                    print('No malware detected in the file.')
            else:
                print(f'Unexpected response code from VirusTotal: {response_code}')
        else:
            print('Invalid response from VirusTotal API.')
    else:
        print(f'Error {response.status_code}: Failed to check file scan report.')

# Function to continuously monitor the clipboard for URL changes
def monitor_clipboard():
    current_clipboard = pyperclip.paste()

    while True:
        time.sleep(1)
        new_clipboard = pyperclip.paste()

        if new_clipboard != current_clipboard and new_clipboard.startswith('http'):
            print(f'New URL detected: {new_clipboard}')
            scan_url(new_clipboard)
            current_clipboard = new_clipboard

# Start monitoring the clipboard for URL changes
monitor_clipboard()
