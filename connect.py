import wifi

def connect_to_wifi(ssid, password):
    # Scan for available WiFi networks
    cells = wifi.Cell.all('wlan0')

    # Find the WiFi network with the specified SSID
    target_cell = None
    for cell in cells:
        if cell.ssid == ssid:
            target_cell = cell
            break

    if target_cell is None:
        print(f"WiFi network '{ssid}' not found.")
        return False

    # Connect to the WiFi network
    try:
        target_cell.connect(password)
        print(f"Connected to WiFi network '{ssid}'.")
        return True
    except wifi.exceptions.ConnectionError as e:
        print(f"Failed to connect to WiFi network: {e}")
        return False

# Get WiFi credentials from user input
wifi_ssid = input("Enter the SSID of the WiFi network: ")
wifi_password = input("Enter the password of the WiFi network: ")

connect_to_wifi(wifi_ssid, wifi_password)



