#!/bin/bash

# Function to connect to WiFi
connect_to_wifi() {
    local ssid="$1"
    local password="$2"

    # Check if nmcli is available
    if ! command -v nmcli &>/dev/null; then
        echo "Error: nmcli command not found. Please make sure NetworkManager is installed."
        exit 1
    fi

    # Check if WiFi is enabled
    if ! nmcli radio wifi | grep -q enabled; then
        echo "Error: WiFi is not enabled."
        exit 1
    fi

    # Connect to WiFi
    nmcli device wifi connect "$ssid" password "$password"
    if [ $? -eq 0 ]; then
        echo "Connected to WiFi network '$ssid'."
    else
        echo "Failed to connect to WiFi network."
        exit 1
    fi
}

# Check if SSID and password are provided as arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <SSID> <password>"
    exit 1
fi

connect_to_wifi "$1" "$2"

sudo python3 tester.py

sudo python3 recon.py
