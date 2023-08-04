SpamHarvesterV2
Additional enhancement build on the SpamHarvester script - Integrating URL scanning and reporting with Virus Total API 

SpamHarvesterV2 is an enhanced version of the original SpamHarvester. This Python script extends the original's functionality to detect, analyze, and report on potential phishing URLs found in email messages.

Features:
1.	Connection to an Email Server: Connects to an IMAP server, logs in using the specified credentials, and scans the messages in the specified folder.
2.	Extracting and Analyzing Email Data: Extracts headers, body, subject, domains, IP addresses, and URLs from each email message and stores the results.
3.	URL Scanning with VirusTotal: Uses the VirusTotal API to scan each unique URL found in the email messages, submits each URL for scanning, retrieves the scan report, and records the results.
4.	Exporting the Results: Exports the headers, body, URLs, and VirusTotal results for each email message into a CSV file for further analysis.
5.	Connection Management: Periodically checks the connection to the email server and tries to reconnect if the connection is lost.
6.	Marking Messages as Read: Marks all scanned messages as read after scanning.
7.	Preventing Duplicate Scans: Maintains a set of scanned URLs and skips URLs that have already been scanned to prevent unnecessary API calls and redundant scanning.
Installation:
You'll need to provide your own email server details and credentials, as well as your VirusTotal API key.

This project requires Python and the following Python packages: python-whois, requests

You can install these packages using pip:
pip install python-whois requests

Replace the placeholder values in the Python commands below with your own details:
imap = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
imap.login("YourEmail@yahoo.com","IMAP_OTP")
imap.select("Aphish")
api_key = "VirusTotalAPI"  # replace with your VirusTotal API key


Run the script in your Python environment. It will automatically connect to the email server, scan the emails, send the URLs for scanning, and export the results to 'addresses.csv':

python SpamHarvesterV2.py


Future Development:
In the future, we aim to further enhance:

1.	Integration with Threat Intelligence APIs: Integrating threat intelligence APIs like AlienVault's OTX, GreyNoise, or even others like IBM X-Force, can provide you with information about potentially malicious IP addresses, URLs, or domains that are detected in the emails.

2.	Attachment Scanning and Analysis: Implement functionality to safely download, hash, and scan attachments using antivirus APIs like VirusTotal, or sandbox services for dynamic analysis. This could identify potentially malicious payloads within attachments.

3.	Enhanced Reporting: With the additional data from various APIs, developing more comprehensive reports. This could include detailed threat intelligence data, geolocation of IP addresses, WHOIS information, and much more.

4.	Integration with Email Reporting Services: After detecting a phishing or spam email, automatically report it to the email provider or relevant reporting services. This could help in the larger fight against spam and phishing.

5.	Automated Response: Develop functionality that can take an automatic action upon detecting a threat. This could include moving the email to a separate folder, marking it as spam, or even deleting it.

6.	Interactive Dashboard: As development proceeds, creating an interactive dashboard to monitor and analyze the results. This could include various visualizations and charts to better understand the data.

7.	Machine Learning Model Integration: If users collect enough data, they could potentially use machine learning models to predict whether an email is spam based on its content and metadata. This could improve spam detection capabilities beyond just searching for known spam indicators.

8.	Real-Time Notification System: Currently, this script analyzes emails and stores the results in a CSV file.  We plan on implementing a real-time notification system that alerts you immediately when a potential phishing email is detected.

9.	GUI Implementation: To make the tool more user-friendly, especially for non-technical users. This would allow users to set parameters, start scans, and view results more intuitively.

10.	Integration with Other Email Services: Currently designed to work with an IMAP server, we hope to extend its capabilities to support other email services, such as POP3 or even specific email providers like Gmail, Outlook, etc.

11.	Scalability: With a large number of emails to analyze, there may be performance issues. Working to efficiently handle larger volumes of data could be a future goal.

12.	Sandbox Analysis: For deeper analysis of URLs and attachments, integrating a sandbox environment. 

13.	Automated Reporting and Blocking: Once a spam or phishing email is detected, the script could automatically report the email to the appropriate abuse authorities and block the sender or the IP address to prevent further emails.
