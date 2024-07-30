# Ensure the script is run as an administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

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

# Create a form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Credential Retriever"
$form.Width = 800
$form.Height = 600
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#121212")
$form.ForeColor = [System.Drawing.Color]::LightBlue

# Create controls
$buttonDump = New-Object System.Windows.Forms.Button
$buttonDump.Text = "Retrieve Credentials"
$buttonDump.Location = New-Object System.Drawing.Point(10, 10)
$buttonDump.Width = 150
$buttonDump.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
$buttonDump.ForeColor = [System.Drawing.Color]::LightBlue
$buttonDump.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$textBoxResult = New-Object System.Windows.Forms.TextBox
$textBoxResult.Location = New-Object System.Drawing.Point(10, 40)
$textBoxResult.Size = New-Object System.Drawing.Size(780, 480)
$textBoxResult.Multiline = $true
$textBoxResult.ScrollBars = "Vertical"
$textBoxResult.ReadOnly = $true
$textBoxResult.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
$textBoxResult.ForeColor = [System.Drawing.Color]::LightBlue
$textBoxResult.Font = New-Object System.Drawing.Font("Consolas", 10)

$buttonCopy = New-Object System.Windows.Forms.Button
$buttonCopy.Text = "Copy to Clipboard"
$buttonCopy.Location = New-Object System.Drawing.Point(10, 530)
$buttonCopy.Width = 120
$buttonCopy.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
$buttonCopy.ForeColor = [System.Drawing.Color]::LightBlue
$buttonCopy.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$buttonSave = New-Object System.Windows.Forms.Button
$buttonSave.Text = "Save to File"
$buttonSave.Location = New-Object System.Drawing.Point(140, 530)
$buttonSave.Width = 100
$buttonSave.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
$buttonSave.ForeColor = [System.Drawing.Color]::LightBlue
$buttonSave.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

$buttonClear = New-Object System.Windows.Forms.Button
$buttonClear.Text = "Clear Output"
$buttonClear.Location = New-Object System.Drawing.Point(260, 530)
$buttonClear.Width = 100
$buttonClear.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
$buttonClear.ForeColor = [System.Drawing.Color]::LightBlue
$buttonClear.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat

# Add event handlers
$buttonDump.Add_Click({
    $textBoxResult.Clear()
    $credentials = Get-StoredCredentials
    if ($credentials.Count -eq 0) {
        $textBoxResult.Text = "No credentials found."
    } else {
        $output = "Credentials Summary:`r`n`r`n"
        $currentSource = ""
        $currentPath = ""
        foreach ($cred in $credentials) {
            if ($cred.Source -ne $currentSource) {
                $output += "`r`n=== $($cred.Source) ===`r`n`r`n"
                $currentSource = $cred.Source
                $currentPath = ""
            }
            if ($cred.Path -ne $currentPath) {
                $output += "  - $($cred.Path)`r`n"
                $currentPath = $cred.Path
            }
            $output += "    $($cred.Name): $($cred.Value)`r`n"
        }
        $textBoxResult.Text = $output
    }
})

$buttonCopy.Add_Click({
    if ($textBoxResult.Text) {
        [System.Windows.Forms.Clipboard]::SetText($textBoxResult.Text)
        [System.Windows.Forms.MessageBox]::Show("Content copied to clipboard!", "Copy Complete")
    }
})

$buttonSave.Add_Click({
    if ($textBoxResult.Text) {
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|JSON files (*.json)|*.json|XML files (*.xml)|*.xml|All files (*.*)|*.*"
        $saveFileDialog.DefaultExt = "txt"
        $saveFileDialog.AddExtension = $true
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $filePath = $saveFileDialog.FileName
            switch -Regex ($filePath) {
                '\.csv$' {
                    $textBoxResult.Text | ConvertFrom-Csv | Export-Csv -Path $filePath -NoTypeInformation
                }
                '\.json$' {
                    $textBoxResult.Text | ConvertFrom-Json | ConvertTo-Json | Out-File -FilePath $filePath
                }
                '\.xml$' {
                    $textBoxResult.Text | ConvertTo-Xml | Out-File -FilePath $filePath
                }
                default {
                    $textBoxResult.Text | Out-File -FilePath $filePath
                }
            }
            [System.Windows.Forms.MessageBox]::Show("File saved successfully!", "Save Complete")
        }
    }
})

$buttonClear.Add_Click({
    $textBoxResult.Clear()
})

# Add controls to the form
$form.Controls.AddRange(@($buttonDump, $textBoxResult, $buttonCopy, $buttonSave, $buttonClear))

# Show the form
[void]$form.ShowDialog()
