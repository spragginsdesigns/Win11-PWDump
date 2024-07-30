# Windows Credential Retriever - Pentester Tool v1.0

## Overview

Windows Credential Retriever is a PowerShell-based tool designed to extract and manage credentials stored on a Windows system. It retrieves passwords, authentication tokens, and other sensitive data from various sources such as the Windows registry, Windows Credential Manager, and DPAPI-protected storage.

## Features

- **Registry Credentials**: Extracts credentials from multiple registry paths.
- **Windows Credential Manager**: Retrieves stored credentials using `cmdkey`.
- **Windows Vault**: Lists credentials stored in Windows Vault.
- **DPAPI Decryption**: Decrypts DPAPI-protected data.
- **NTLM Hash Extraction**: Attempts to extract NTLM hashes from LSA Secrets.
- **Advanced Error Handling**: Provides detailed error messages for debugging.
- **GUI**: User-friendly interface with options to retrieve, clear, copy, and save credentials.

## Prerequisites

- Windows 10 or 11
- PowerShell 5.1 or later
- Administrative privileges

## Installation

1. Clone the repository or download the script file.
2. Ensure you have the necessary permissions to run the script as an administrator.

## Usage

### Running the Script

1. Open PowerShell as an Administrator.
2. Navigate to the directory where the script is located.
3. Run the script using the command:
   ```powershell
   .\Windows11-Credential-Retriever.ps1
   ```

### Features

1. **Retrieve Credentials**: Click the "Retrieve Credentials" button to scan and display all found credentials.
2. **Clear Output**: Click the "Clear Output" button to clear the results window.
3. **Copy to Clipboard**: Click the "Copy to Clipboard" button to copy the results to the clipboard.
4. **Save to File**: Click the "Save to File" button to save the results to a file. Supported formats include TXT, CSV, JSON, and XML.

## Detailed Script Breakdown

### Functions

- **Get-StoredCredentials**: Main function to retrieve and process credentials.
  - **Registry Paths**: Scans specific registry paths for stored credentials.
  - **Command Key**: Uses `cmdkey` to list stored credentials.
  - **Windows Vault**: Uses `vaultcmd` to list credentials from Windows Vault.
  - **DPAPI Decryption**: Attempts to decrypt DPAPI-protected data.
  - **NTLM Hash Extraction**: Extracts NTLM hashes using `nltest`.

### Error Handling

- **Registry Paths**: Checks if paths exist before scanning.
- **DPAPI**: Ensures non-null content before attempting decryption.
- **NTLM**: Provides detailed error messages if extraction fails.

### User Interface

- **Form**: Creates the main GUI window.
- **Controls**: Buttons for retrieving, clearing, copying, and saving credentials.
- **Event Handlers**: Handles user interactions with the GUI controls.

## Example Output

```
Credentials Summary:

=== DPAPI ===
Keys show here

=== Registry ===
Registry Path and Keys show here

=== Windows Credential Manager ===
  - Target: ExampleTarget
    Type: Generic
    User: exampleUser

=== Windows Vault ===
  - Resource: SampleResource
    Identity: sampleIdentity

=== LSA Secrets ===
  - Secret: ExampleSecret

=== WiFi ===
  - Profile: SampleProfile
    Password: SamplePassword
```

## Troubleshooting

- **Administrator Rights**: Ensure you are running the script with administrative privileges.
- **Missing Registry Paths**: Some paths may not exist if the associated software or features are not installed.
- **Service Availability**: Ensure required services are running and accessible.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For any questions or issues, please open an issue in the GitHub repository.

## Disclaimer

Use this tool responsibly and only on systems you have explicit permission to test. Unauthorized access to computer systems is illegal and unethical.
