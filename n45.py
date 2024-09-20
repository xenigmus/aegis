import subprocess
import re

def get_ip_addresses(interface):
    try:
        ip_addresses_output = subprocess.check_output(["ip", "addr", "show", interface]).decode()
        ip_pattern = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)/\d+")
        return ip_pattern.findall(ip_addresses_output)
    except subprocess.CalledProcessError:
        return []

def run_nmap_scan(ip_addresses):
    try:
        # Construct the network segment for Nmap scan
        network_segment = ".".join(ip_addresses[0].split('.')[:-1]) + ".0/24"
        print(f"Performing Nmap scan for network segment {network_segment}...")
        nmap_output = subprocess.check_output(["nmap", "-sn", network_segment]).decode()
        live_hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", nmap_output)
        return live_hosts
    except subprocess.CalledProcessError:
        return []

def run_routersploit(ip_addresses):
    processes = []
    for ip in ip_addresses:
        print(f"Scanning {ip} for vulnerabilities...")
        try:
            # Start RouterSploit in the background
            proc = subprocess.Popen(['/home/eni9ma/routersploit/rsf.py', '-m', 'scanners/autopwn', '-s', f'set target {ip}; run'], 
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append((ip, proc))
        except subprocess.CalledProcessError as e:
            print(f"Error scanning {ip}: {e}")

    return processes

def print_results(results):
    for ip, proc in results:
        output, _ = proc.communicate()
        if output is not None:
            unverified_vulns = re.findall(r"Could not verify exploitability:(.*?)Could not confirm any vulnerablity", output, re.DOTALL)
            if unverified_vulns:
                print(f"Unverified vulnerabilities for {ip}:")
                for vuln in unverified_vulns:
                    print(vuln.strip())
            else:
                print(f"No unverified vulnerabilities found for {ip}.")

if __name__ == "__main__":
    interface = "wlan0"  # Specify the network interface to use
    ip_addresses = get_ip_addresses(interface)
    if ip_addresses:
        print("IP addresses found on interface:")
        print(", ".join(ip_addresses))
        live_ip_addresses = run_nmap_scan(ip_addresses)
        if live_ip_addresses:
            print("Live IP addresses found:")
            print(", ".join(live_ip_addresses))
            results = run_routersploit(live_ip_addresses)
            print_results(results)
        else:
            print("No live IP addresses found.")
    else:
        print(f"No IP addresses found on interface {interface}.")
