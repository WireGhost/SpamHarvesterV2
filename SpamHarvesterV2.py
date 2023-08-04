#SpamHarvesterV2.py 
#The following Python Script is for harvesting data from Spam email headers. 
#Version 2 allows for a Virus Total API to scan the email body URLs and prodece a report in the CSV. 
#The relevant data collected from the headers is appended to a csv file: 
#From the csv file, elements, whether domain, URLs, IP, etc. Can be used to report or block. 
#Or it could be used for more interesting automated solutions. 
#Deployed as a scheduled task or cron job, it will automatically run and append to the csv. 
#This script is for personal email accounts. Preferably an old account to use as a spam honeypot. 
#Created and Tested on Python 3.11.2 - Win 10 x64
import logging
import imaplib
import email
import csv
import re
import socket
import whois
import requests
import time
import json
from urllib.parse import urlparse

# Configuration - Variables to Define. 
IMAP_SERVER = "imap.mail.yahoo.com"
IMAP_USER = "YourEmail@yahoo.com"
IMAP_PASSWORD = "IMAP_OTP"
IMAP_FOLDER = "Aphish"
VT_API_KEY = "Virus_Total_API_Key"
OUTPUT_FILE = "addresses.csv"

# Set up logging
logging.basicConfig(filename='spamharvester.log', level=logging.INFO)

# Function to establish IMAP connection
def connect_imap(server, user, password, folder):
    imap = imaplib.IMAP4_SSL(server)
    imap.login(user, password)
    imap.select(folder)
    return imap

# Function to check and re-establish IMAP connection if needed in cases of timeouts, etc. 
def check_connection(imap, server, user, password, folder):
    try:
        imap.noop()
    except imaplib.IMAP4.abort:
        print("Connection lost. Reconnecting...")
        try:
            imap.logout()
        except imaplib.IMAP4.error:
            print("Error during logout. Proceeding to reconnection...")
        return connect_imap(server, user, password, folder)
    return imap

# Function to submit URLs for scanning to VirusTotal
def submit_vt_scan(url):
    headers = {
        "x-apikey": VT_API_KEY
    }
    data = {
        "url": url
    }
    try:
        response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
        response.raise_for_status()
        scan_id = response.json().get('data', {}).get('id', '')
        return scan_id
    except requests.exceptions.HTTPError as errh:
        logging.error(f"HTTP Error: {errh} for URL {url}")
    except requests.exceptions.ConnectionError as errc:
        logging.error(f"Error Connecting: {errc} for URL {url}")
    except requests.exceptions.Timeout as errt:
        logging.error(f"Timeout Error: {errt} for URL {url}")
    except requests.exceptions.RequestException as err:
        logging.error(f"Unknown Error: {err} for URL {url}")
    return None

# Function to retrieve VirusTotal reports. 
def get_vt_report(scan_id):
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{scan_id}', headers=headers)
        response.raise_for_status()
        return json.loads(response.content)
    except requests.exceptions.HTTPError as errh:
        logging.error(f"HTTP Error: {errh} for scan_id {scan_id}")
    except requests.exceptions.ConnectionError as errc:
        logging.error(f"Error Connecting: {errc} for scan_id {scan_id}")
    except requests.exceptions.Timeout as errt:
        logging.error(f"Timeout Error: {errt} for scan_id {scan_id}")
    except requests.exceptions.RequestException as err:
        logging.error(f"Unknown Error: {err} for scan_id {scan_id}")
    return "Report not available"


# Function to parse received_from headers (there are 3 fields should more than one be present in a spam email). 
def find_received_from(headers):
    received_from = []
    received_header = headers.get("received", "")
    received_fields = re.findall(r"from\s(.*?)(?=\swith|\n|$)", received_header, re.IGNORECASE)
    for field in received_fields:
        received_from.append(field.strip())
    return received_from


# Function to fetch all messages from a folder - the folder defined as "IMAP_FOLDER" variable. 
def fetch_all_messages(imap):
    search_criteria = "ALL"
    status, messages = imap.search(None, search_criteria)
    return messages[0].split()


# Function to extract information from the messages - header and URLs in Body. 
def extract_header_and_body(imap, message):
    _, msg_data = imap.fetch(message, "(RFC822)")
    # Check if the data can be decoded.
    if not isinstance(msg_data[0][1], bytes):
        logging.error(f"Unexpected data type for message {message}: {type(msg_data[0][1])}. Skipping this message.")
        return None, None
    msg = email.message_from_string(msg_data[0][1].decode('utf-8', errors='ignore'))
    headers = msg.items()
    header_dict = {}
    for header in headers:
        header_dict[header[0].lower()] = header[1]

    def extract_body_from_payload(payload):
        body_parts = []
        if isinstance(payload, list):
            for part in payload:
                if isinstance(part.get_payload(), list):
                    body_parts.extend(extract_body_from_payload(part.get_payload()))
                else:
                    body_parts.append(part.get_payload())
        else:
            body_parts.append(payload)
        return body_parts
    
    body = extract_body_from_payload(msg.get_payload())
    body = ' '.join(body)

    return header_dict, body

# Extract and Scan URLs
def extract_and_scan_urls(body, scanned_urls):
    urls = re.findall(r"\bhttps?://[^\s]+\b", body)
    vt_results = []
    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        if hostname not in scanned_urls:
            vt_scan_id = submit_vt_scan(hostname)
            if vt_scan_id is not None:
                print(f"Successfully requested VT scan for {hostname}")
                scanned_urls.add(hostname)
                time.sleep(60)
                vt_report = get_vt_report(vt_scan_id)
                vt_results.append(vt_report)
                time.sleep(15)
        else:
            print(f"Skipping {hostname} as it has already been scanned.")
    return urls, vt_results

# Extracts info from message? 
def extract_info_from_message(imap, message, scanned_urls):
    header_dict, body = extract_header_and_body(imap, message)
    if header_dict is None:
        return None, None, None, None
    urls, vt_results = extract_and_scan_urls(body, scanned_urls)
    return header_dict, body, urls, vt_results	

# Function to mark a message(s) as read. 
def mark_message_as_read(imap, message):
    try:
        imap.store(message, "+FLAGS", "\\Seen")
    except imaplib.IMAP4.abort:
        print("Connection lost while marking message as read. Reconnecting...")
        imap = connect_imap(IMAP_SERVER, IMAP_USER, IMAP_PASSWORD, IMAP_FOLDER)
        imap.store(message, "+FLAGS", "\\Seen")
    except Exception as e:
        print(f"Unexpected error while marking message as read: {e}")

# Function to write results to a CSV file. 
def write_to_csv(filename, rows):
    fieldnames = [
        "Received From 1", "Received From 2", "Received", "From", "Domain IP", "Subject", "Delivered-To",
        "X-Received", "Return Path", "Received-SPF", "Authentication Results", "Reply-To", "Date",
        "MIME Version", "Content Type", "Content-Transfer-Encoding", "Message ID", "To", "CC", "BCC", "URLs",
        "Reporting Abuse Email", "VT Results"
    ]
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    imap = connect_imap(IMAP_SERVER, IMAP_USER, IMAP_PASSWORD, IMAP_FOLDER)
    scanned_urls = set()
    results = []
    messages = fetch_all_messages(imap)
    for idx, message in enumerate(messages):
        print(f"Processing message {idx+1}/{len(messages)}")
        imap = check_connection(imap, IMAP_SERVER, IMAP_USER, IMAP_PASSWORD, IMAP_FOLDER)
        header_dict, body, urls, vt_results = extract_info_from_message(imap, message, scanned_urls)
        
        if header_dict is None:
            continue

        results.append((header_dict, body, urls, vt_results))
        mark_message_as_read(imap, message)

    rows = []
    for header_dict, body, urls, vt_results in results:
        row = {}
        received_from = find_received_from(header_dict)
        row["Received From 1"] = received_from[0] if received_from else ""
        row["Received From 2"] = received_from[1] if len(received_from) > 1 else ""
        row["Received"] = header_dict.get("received", "")
        row["From"] = header_dict.get("from", "")
        row["Domain IP"] = ""
        row["Subject"] = header_dict.get("subject", "")
        row["Delivered-To"] = header_dict.get("delivered-to", "")
        row["X-Received"] = header_dict.get("x-received", "")
        row["Return Path"] = header_dict.get("return-path", "")
        row["Received-SPF"] = header_dict.get("received-spf", "")
        row["Authentication Results"] = header_dict.get("authentication-results", "")
        row["Reply-To"] = header_dict.get("reply-to", "")
        row["Date"] = header_dict.get("date", "")
        row["MIME Version"] = header_dict.get("mime-version", "")
        row["Content Type"] = header_dict.get("content-type", "")
        row["Content-Transfer-Encoding"] = header_dict.get("content-transfer-encoding", "")
        row["Message ID"] = header_dict.get("message-id", "")
        row["To"] = header_dict.get("to", "")
        row["CC"] = header_dict.get("cc", "")
        row["BCC"] = header_dict.get("bcc", "")
        row["URLs"] = ", ".join(urls)
        row["VT Results"] = vt_results

        if "received" in header_dict:
            ip_address = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", header_dict["received"])
            if ip_address:
                try:
                    w = whois.whois(ip_address[0])
                    row["Reporting Abuse Email"] = w.emails[0] if w.emails else "N/A"
                    row["Domain IP"] = ip_address[0]
                except (socket.gaierror, whois.parser.PywhoisError, IndexError):
                    row["Reporting Abuse Email"] = "N/A"
        rows.append(row)

    write_to_csv(OUTPUT_FILE, rows)

    imap.close()
    imap.logout()


if __name__ == "__main__":
    main()
