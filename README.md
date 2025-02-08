# Threat Intelligence IP Analyzer

## Overview
The **Threat Intelligence IP Analyzer** is a Python-based tool that collects and analyzes IP addresses using various threat intelligence sources through their API's, including:
- **AbuseIPDB** (for malicious IP reports)
- **VirusTotal** (for malware detections)
- **Shodan** (for open ports and ISP details)
- **GeoIP Lookup** (for location details)

The tool generates structured logs for each IP and stores them in a well-organized directory structure by **year, month, and day**. 

---
## Features
✅ **Analyze IP addresses** from a user-provided list
✅ **Integrate with multiple threat intelligence APIs**
✅ **Organized logs by year, month, and day**
✅ **Rate limiting to prevent API bans**

---
## Installation

### **1. Clone the repository**
```bash
git clone https://github.com/Sh4dowTr4ck3r/threat-intelligence-ip-analyzer.git
cd threat-intelligence-ip-analyzer
```

### **2. Install dependencies**
Make sure you have Python 3 installed. Then install required libraries:
```bash
pip install -r requirements.txt
```

### **3. Set up API Keys**
Obtain API keys from:
- **[AbuseIPDB](https://www.abuseipdb.com/)**
- **[VirusTotal](https://www.virustotal.com/)**
- **[Shodan](https://www.shodan.io/)**

Then, update the script with your API keys:
```python
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
SHODAN_API_KEY = "your_shodan_api_key"
```

---
## Usage

### **1. Prepare an IP list**
Create a text file (e.g., `ips.txt`) containing one IP per line:
```txt
8.8.8.8
1.1.1.1
185.220.101.16
```

### **2. Run the script**
Execute the script and provide the input file when prompted:
```bash
python ip_collector.py
```
If no input file is provided, it defaults to `ips.txt` which is a sample of random ips.

### **3. View logs and reports**
- **Logs**: Stored in `logs/{year}/{month_day}/IP_<IP>_YYYY-MM-DD_HH-MM-SS.txt`

Example:
```
logs/
├── 2025/
│   ├── 02_10/
│   │   ├── IP_8_8_8_8_2025-02-10_15-30-22.txt
│   │   ├── IP_1_1_1_1_2025-02-10_15-32-45.txt
```

---
## Example Output (Terminal Log)
```
🔍 Checking 8.8.8.8...
─────────────────────────────────────
📌 AbuseIPDB: (0, 'US', 0, 'ISP', 'Google LLC', 'google.com', 'Never Reported')
📌 VirusTotal: (0, 'US', '✅ No Risk')
📌 Shodan: ([53, 443], 'Google LLC', 'Mountain View', 'United States')
📌 GeoIP: ('United States', 'California', 'Mountain View', 37.4056, -122.0775, 'Google LLC')
📁 Log saved: logs/2025/02_10/IP_8_8_8_8_2025-02-10_15-30-22.txt
```

---
## Future Enhancements
📌 Add domain analysis capabilities 📌 Include more threat intelligence sources 📌 Improve error handling and API rate management

Pull requests are welcome! If you have any suggestions or improvements, feel free to contribute.


