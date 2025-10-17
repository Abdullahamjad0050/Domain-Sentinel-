# Domain Sentinel

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A desktop GUI application for Linux to analyze domain reputations using the VirusTotal API and extract domains from network traffic captures (PCAP files).

![Domain Sentinel Screenshot](screenshot.png)
*(Note: You should replace `screenshot.png` with an actual screenshot of your application.)*

## Key Features

* **PCAP Analyzer**: Directly open `.pcap` or `.pcapng` files and use `tshark` to extract all domain names from DNS, HTTP, and TLS traffic.
* **VirusTotal Integration**: Check the reputation of domains against dozens of security vendors via the VirusTotal API.
* **Threat Dashboard**: Get a high-level overview of scan results with a pie chart visualizing malicious, suspicious, and harmless domains.
* **Detailed Analysis**: View in-depth data for each domain, including WHOIS information, DNS records, SSL certificates, and popularity ranks.
* **Export Functionality**: Save PCAP analysis results and domain reputation reports to `.txt` or `.csv` files.
* **Modern UI**: Features a clean, resizable layout with both Dark and Light themes.

## Prerequisites

Before installing, ensure your system has the following software installed.

1.  **Python 3.8+**: Required to run the application.
    ```bash
    # You can check your version with:
    python3 --version
    ```
2.  **Tshark (Wireshark-CLI)**: **Required** for the "PCAP Analyzer" feature.
    * **For Debian/Ubuntu:**
        ```bash
        sudo apt update && sudo apt install tshark
        ```
    * **For Fedora/CentOS/RHEL:**
        ```bash
        sudo dnf install wireshark-cli
        ```
    * **For Arch Linux:**
        ```bash
        sudo pacman -S wireshark-cli
        ```

## Installation

Follow these steps to set up and run the application from the source code.

**1. Clone the Repository**
```bash
git clone [https://github.com/your-username/domain-sentinel.git](https://github.com/your-username/domain-sentinel.git)
cd domain-sentinel
```

**2. Create a `requirements.txt` file**
Create a file named `requirements.txt` in the project directory and add the following lines:
```
PyQt6
requests
keyring
matplotlib
```

**3. Set Up a Virtual Environment**
It is highly recommended to use a virtual environment to manage dependencies.
```bash
# Create the environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

**4. Install Dependencies**
Install all required Python libraries from your `requirements.txt` file.
```bash
pip install -r requirements.txt
```

## Usage

Once the installation is complete, you can run the application.

**1. Run the Application**
```bash
python3 domain_sentinel.py
```
*(Assuming the main script is named `domain_sentinel.py`)*

**2. Basic Workflow**
1.  Navigate to the **PCAP Analyzer** tab to extract domains from a network capture file, or use the **Load Domains** button in the **VirusTotal Inspector** tab to load from a text file.
2.  Enter your VirusTotal API key in the input field. It is recommended to check "Save API key securely".
3.  Set a delay (e.g., 15 seconds) to respect the public API rate limits.
4.  Click **Start** to begin the analysis.
5.  Review the results in the log, the dashboard, and the detailed view tabs.

## Docker Support

For a portable, containerized setup, please see the detailed instructions in **[DOCKER.md](DOCKER.md)**.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
