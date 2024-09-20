import subprocess

def generate_figlet(text, font="big"):
    figlet_output = subprocess.check_output(["figlet", "-f", font, text]).decode()
    return figlet_output

def run_scriptv1(interface, ssid, wordlist):
    subprocess.run(["figlet", "-f", "big", "NetFortify"])
    subprocess.run(["python", "scriptv1.py", interface, ssid, wordlist], check=True)

def connect_to_network(ssid, password):
    subprocess.run(["nmcli", "device", "wifi", "connect", ssid, "password", password], check=True)

def run_n45():
    subprocess.run(["python", "n45.py"], check=True)

if __name__ == "__main__":
    # Parameters
    interface = "wlan1"  # Specify the network interface to use
    ssid = input("Enter the SSID of the network: ")  # Prompt user for SSID
    wordlist = "/usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000000.txt"  # Specify the path to the wordlist

    # Step 1: Run scriptv1.py to capture the password
    print("Running scriptv1.py...")
    run_scriptv1(interface, ssid, wordlist)
    print("Password captured successfully.")

    # Step 2: Connect to the network using the captured password
    password_file = "password.txt"
    with open(password_file, "r") as f:
        password = f.read().strip()
    print(f"Connecting to network '{ssid}' using the captured password...")
    connect_to_network(ssid, password)
    print("Connected to network successfully.")

    # Step 3: Run n45.py for RouterSploit scanning
    print("Running n45.py for RouterSploit scanning...")
    run_n45()
    print("RouterSploit scanning complete.")
