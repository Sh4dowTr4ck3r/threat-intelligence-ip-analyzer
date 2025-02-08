import requests
import csv
import time
import pandas as pd
from datetime import datetime
from ipwhois import IPWhois
import os



# Set your API keys
ABUSEIPDB_API_KEY = "2ef20571d5c11034a529dcd529072e0ba5b7b35b1fa696af027a47ad0e891bd4932607800510f8a5"
VIRUSTOTAL_API_KEY = "695588012905de1ff638fc9498ecefd671d5a64314b1d57919549b979acd16b7"
SHODAN_API_KEY = "75JPQMhvR4nw6JxI7pUQs0t3kLTyR1PF"



# Get user input for the IP list file
default_input_file = "ips.txt"
user_input_file = input(f"Enter the IP file name (default: {default_input_file}): ").strip()
INPUT_FILE = user_input_file if user_input_file else default_input_file



# Output CSV file
OUTPUT_FILE = f"threat_IP_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

# Function to classify severity
def classify_severity(score):
    if score in ["Error", "No Data"]:
        return "No Data ❔"
    elif int(score) == 0:
        return "✅ No Risk"
    elif int(score) <= 25:
        return "🟡 Low Risk"
    elif int(score) <= 50:
        return "🟠 Medium Risk"
    elif int(score) <= 75:
        return "🔴 High Risk"
    else:
        return "🔥 Critical"

# Query AbuseIPDB
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        if "data" in data:
            abuse_confidence_score = data["data"].get("abuseConfidenceScore", "No Data")
            country_code = data["data"].get("countryCode", "Unknown")
            total_reports = data["data"].get("totalReports", "No Data")
            usage_type = data["data"].get("usageType", "Unknown")
            isp = data["data"].get("isp", "Unknown")
            domain = data["data"].get("domain", "Unknown")
            last_reported_at = data["data"].get("lastReportedAt", "Never Reported")

            return (abuse_confidence_score, country_code, total_reports, usage_type, isp, domain, last_reported_at)
        else:
            return ("No Data", "Unknown", "No Data", "Unknown", "Unknown", "Unknown", "Never Reported")
    except requests.exceptions.RequestException:
        return ("Error", "Unknown", "Error", "Unknown", "Unknown", "Unknown", "Error")

# Query VirusTotal
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if "data" in data:
            last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
            total_detections = last_analysis_stats.get("malicious", 0) + last_analysis_stats.get("suspicious", 0)

            return (total_detections, data["data"]["attributes"].get("country", "Unknown"), classify_severity(total_detections * 10))
        else:
            return "No Data", "Unknown", "No Data ❔"
    except requests.exceptions.RequestException:
        return "Error", "Unknown", "Error"

# Query Shodan
def check_shodan(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if "error" not in data:
            return (data.get("ports", []), data.get("isp", "Unknown"), data.get("city", "Unknown"), data.get("country_name", "Unknown"))
        else:
            return "No Data", "Unknown", "Unknown", "Unknown"
    except requests.exceptions.RequestException:
        return "Error", "Unknown", "Unknown", "Unknown"

# Query GeoIP (ip-api.com)
def check_geoip(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if data["status"] == "success":
            return (data.get("country", "Unknown"), data.get("regionName", "Unknown"), data.get("city", "Unknown"),
                    data.get("lat", "Unknown"), data.get("lon", "Unknown"), data.get("isp", "Unknown"))
        else:
            return "No Data", "No Data", "No Data", "No Data", "No Data", "No Data"
    except requests.exceptions.RequestException:
        return "Error", "Error", "Error", "Error", "Error", "Error"

# Read IPs
with open(INPUT_FILE, "r") as file:
    ips = [line.strip() for line in file]

# CSV Output Headers
headers = [
    "IP", "AbuseIPDB Score", "AbuseIPDB Country", "AbuseIPDB Reports", "AbuseIPDB Usage Type", 
    "AbuseIPDB ISP", "AbuseIPDB Domain", "AbuseIPDB Last Reported",
    "VirusTotal Detections", "VirusTotal Country", "VirusTotal Risk", 
    "Shodan Open Ports", "Shodan ISP", "Shodan City", "Shodan Country", 
    "GeoIP Country", "GeoIP Region", "GeoIP City", "GeoIP Latitude", "GeoIP Longitude", "GeoIP ISP",
    "Checked Time"
]
rows = []

# Ensure logs directory structure (Year → Month_Day)
current_year = datetime.now().strftime('%Y')
current_month_day = datetime.now().strftime('%m_%d')  # Format: MM_DD
LOGS_DIR = f"logs/{current_year}/{current_month_day}"
os.makedirs(LOGS_DIR, exist_ok=True)

# Process Each IP
for ip in ips:
    print(f"\n🔍 Checking {ip}...")
    print("─────────────────────────────────────")

    # Fetch Data
    abuse_data = check_abuseipdb(ip)
    vt_data = check_virustotal(ip)
    shodan_data = check_shodan(ip)
    geoip_data = check_geoip(ip)

    # Generate timestamp for log file
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Save terminal output to a log file inside structured logs folder
    log_filename = f"{LOGS_DIR}/IP_{ip.replace('.', '_')}_{timestamp}.txt"
    with open(log_filename, "w") as log_file:
        log_file.write(f"🔍 IP Analysis Report: {ip}\n")
        log_file.write(f"Date & Time: {timestamp}\n")
        log_file.write("─────────────────────────────────────\n")
        log_file.write(f"📌 AbuseIPDB: {abuse_data}\n")
        log_file.write(f"📌 VirusTotal: {vt_data}\n")
        log_file.write(f"📌 Shodan: {shodan_data}\n")
        log_file.write(f"📌 GeoIP: {geoip_data}\n")
        log_file.write(f"Checked Time: {timestamp}\n")

    print(f"📁 Log saved: {log_filename}")

    # Store in Table
    rows.append([ip, *abuse_data, *vt_data, *shodan_data, *geoip_data, timestamp])

    time.sleep(2)  # Rate limit de


print(f"\n✅ Threat Report in logs")
