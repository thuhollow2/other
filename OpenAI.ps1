if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    try
    {
        $scriptPath = $myInvocation.MyCommand.Definition
        $scriptDirectory = Split-Path $scriptPath
        Start-Process PowerShell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -WorkingDirectory $scriptDirectory
        exit
    }
    catch
    {
        Write-Error "Failed to start as administrator: $_"
        exit
    }
}
Set-Location -Path $PSScriptRoot

Write-Host "This is a simple Windows PowerShell script to detect the validity of proxy nodes access to ChatGPT; it doesn't upload any information outside of the folder you use!"
Start-Sleep -Seconds 1
Write-Host "Script version: V1.1.1"
Start-Sleep -Seconds 1
Write-Host "Abnormal exit of this program may retain some background processes, which will be cleaned up when the program is initialized."

$arch1 = "windows-amd64"    # Clash Architecture
$arch2 = "win64"    # Subconverter Architecture
$max_redirection = 10   # Maximum number of redirection to download a file
$time_ms = 10000    # Maximum time to filter a node
$time_s1 = 10   # Maximum time to download a file
$time_s2 = 2    # Maximum time to check for updates
$time_s3 = 5    # Maximum time to test a node
$curl_sum = 40  # Maximum number of processes to filter nodes
$clash_sum = 20 # Maximum number of processes to test nodes
$used_ports = Get-NetTCPConnection | Select-Object -ExpandProperty LocalPort
$available_ports = 2000..7000 | Where-Object { $used_ports -notcontains $_ } | Get-Random -Count 2
$proxy_port = $available_ports[0]
$ui_port = $available_ports[1]
$user = Get-Random -Minimum 100000000000 -Maximum 999999999999
$pass = Get-Random -Minimum 100000000000 -Maximum 999999999999
$secret = Get-Random -Minimum 100000000000 -Maximum 999999999999
$url_test = "https://chat.openai.com"
$my_url = @'
https://raw.githubusercontent.com/thuhollow2/myconfig/main/Proxy/proxy.yaml
'@
$lines = ($my_url | Where-Object {$_ }) -split "`r?`n"
$processed = @()
foreach ($line in $lines) {
    if($line.ToString().Trim()) {
    $processed += $line.ToString().Trim() 
    }
}
$my_url = $processed -join [environment]::NewLine
$prefix = @"
mixed-port: $proxy_port
allow-lan: false
mode: Rule
log-level: info
ipv6: true
authentication: ["${user}:$pass"]
external-controller: :$ui_port
secret: $secret
proxies:

"@
$suffix1 = @"

proxy-groups:
  - name: URL-TEST
    type: url-test
    url: $url_test
    interval: 60
    tolerance: 50
    proxies:

"@
$suffix2 = @'

rules:
 - MATCH,URL-TEST

'@
$suffix3 = @'

proxy-groups:
  - name: SELECT
    type: select
    proxies:

'@
$suffix4 = @'

rules:
 - MATCH,SELECT

'@
$base = @'
{% if request.target == "quan" %}
[SERVER]

[SOURCE]

[BACKUP-SERVER]

[SUSPEND-SSID]

[POLICY]

[DNS]
1.1.1.1

[REWRITE]

[URL-REJECTION]

[TCP]

[GLOBAL]

[HOST]

[STATE]
STATE,AUTO

[MITM]

{% endif %}
{% if request.target == "surfboard" %}
[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
{% endif %}
'@
function CapsLock_on {
    $WshShell = New-Object -comObject Wscript.Shell
    if (-not([Console]::CapsLock)) {
        $WshShell.SendKeys("{CAPSLOCK}")
    }
}
function CapsLock_off {
    $WshShell = New-Object -comObject Wscript.Shell
    if ([Console]::CapsLock) {
        $WshShell.SendKeys("{CAPSLOCK}")
    }
}

Get-Process -Name process_hidden_clash -ErrorAction SilentlyContinue | Stop-Process
Get-Process -Name process_hidden_subconverter -ErrorAction SilentlyContinue | Stop-Process
Get-Process -Name process_hidden_curl -ErrorAction SilentlyContinue | Stop-Process

Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Allow Inbound for process_hidden_*" -or $_.DisplayName -like "Allow Outbound for process_hidden_*" } | Remove-NetFirewallRule

Write-Host "Initialization is complete! If you only want to shut down background processes, you can safely exit this program with your mouse or Ctrl + C, otherwise press any key to start the test."
$key = [System.Console]::ReadKey($True)
$esc=([char]27)
Write-Host "The test is divided into three parts: <$esc[32mDownload Tools$esc[0m>, <$esc[32mDownload and Examine Subscription Files$esc[0m>, <$esc[32mTest Nodes$esc[0m>."
Start-Sleep -Seconds 1
Write-Host "You can use a proxy or VPN in the first two parts to download the file."
Start-Sleep -Seconds 1
Write-Host "If you $esc[31mhave already completed the first two parts and have saved your subscription urls in the file (usually tools/file/url.txt),$esc[0m you can skip the complicated bootstrapping steps and start downloading and testing directly $esc[31mby using this folder$esc[0m with this option! [Y]|N"
CapsLock_on
while ($True) {
    if ([System.Console]::KeyAvailable) {
        $key = [System.Console]::ReadKey($True)
        if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
            Write-Host "Your choice: "$key.Key
            $mode = 1
            break
        } elseif ($key.Key -eq "N") {
            Write-Host "Your choice: "$key.Key
            $mode = 0
            break
        } else {
            Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
        }
    }
}
Write-Host "Part I: <$esc[32mDownload Tools$esc[0m>"
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
$dir_path = (Get-Location).Path
$dir_path_test = Join-Path -Path $dir_path -ChildPath "test_test_test_test_test_test_test_test"
try {
    $null = New-Item -ItemType Directory -Path $dir_path_test -ErrorAction Stop
    $dir_path_value = 1
}
catch {
    $dir_path_value = 0
}
if (Test-Path $dir_path_test) { Remove-Item -Path $dir_path_test -Force -Recurse }
Write-Host "You are currently in $dir_path."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
Write-Host "You need a folder to store the files."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
if ($dir_path_value -eq 0) {
    Write-Host "Creating or using a folder in $dir_path requires administrator privileges, which I have disabled for security reasons."
    if ($mode -eq 0) { Start-Sleep -Seconds 1 }
} else {
    Write-Host "Do you want to (A)use or create a folder in $dir_path (B)use or create a folder via a full path? [A]|B"
    CapsLock_on
}
$path_value = 9
while ($True) {
    while ($True) {
        if ($dir_path_value -eq 0 -or $path_value -eq 3 -or $path_value -eq 4 -or [System.Console]::KeyAvailable) {
            if ($dir_path_value -eq 1 -and $path_value -ne 3 -and $path_value -ne 4) {
                $key = [System.Console]::ReadKey($True)
            }
            if ($dir_path_value -eq 1 -and ($path_value -eq 4 -or ($path_value -eq 9 -and ($key.Key -eq "Enter" -or $key.Key -eq "A")))) {
                if ($path_value -eq 9) { Write-Host "Your choice: "$key.Key }
                $path_value = 1
                while ($True) {
                    Write-Host "Please enter the name or path of the folder in $dir_path such as 1 and myconfig\1."
                    CapsLock_off
                    $dir_name = (Read-Host).ToString() -creplace '[<>:"|?*]', '' -creplace '/', '\' -creplace '^[\\\s]+|[\\\s]+$', '' -creplace '\s+\\', '\' -creplace '\\\s+', '\' -creplace '\\+', '\'
                    $dir_fullpath = Join-Path -Path $dir_path -ChildPath $dir_name
                    $dir_fullpath_test = Join-Path -Path $dir_fullpath -ChildPath "test_test_test_test_test_test_test_test"
                    $dir_split_directories = $dir_fullpath_test -split "(?<=\\)" | Where-Object {$_ }
                    $dir_fullpath_value = 2
                    $dir_path_test = ""
                    $dir_path_test_name = ""
                    $dir_path_test_path = ""
                    $dir_path_test_real = ""
                    $dir_path_test_exist = ""
                    $dir_path_empty = ""
                    foreach ($dir_part in $dir_split_directories) {
                        if ($dir_path_test) {
                            $dir_path_test_name = $dir_part.TrimEnd('\')
                            $dir_path_test_path = $dir_path_test
                            $dir_path_test = Join-Path -Path $dir_path_test -ChildPath $dir_path_test_name
                        } else {
                            $dir_path_test_real = $dir_part
                            $dir_path_test = $dir_part
                        }
                        if ((Test-Path $dir_path_test) -and $dir_path_test_name) {
                            $dir_path_test_name = (Get-ChildItem $dir_path_test_path).Name | Where-Object {$_.ToUpper() -ceq $dir_path_test_name.ToUpper()}
                            if (Test-Path -PathType Leaf -Path $dir_path_test) {
                                $dir_path_test_exist = Join-Path -Path $dir_path_test_real -ChildPath $dir_path_test_name
                                $dir_fullpath_value = 3
                            }
                        } elseif (-not(Test-Path $dir_path_test) -and -not($dir_path_empty) -and $dir_fullpath_value -ne 3 ) {
                            $dir_path_empty = $dir_path_test
                            try {
                                $null = New-Item -ItemType Directory -Path $dir_fullpath_test -ErrorAction Stop
                                $dir_fullpath_value = 1
                            }
                            catch {
                                $dir_fullpath_value = 0
                            }
                            if (Test-Path $dir_path_empty) { Remove-Item -Path $dir_path_empty -Force -Recurse }
                        }
                        $dir_path_test_real = Join-Path -Path $dir_path_test_real -ChildPath $dir_path_test_name
                    }
                    $dir_fullpath = $dir_path_test_real -creplace '([^:])\\test_test_test_test_test_test_test_test$', '$1' -creplace ':\\test_test_test_test_test_test_test_test$', ':\'
                    if ($dir_fullpath_value -eq 3) {
                        Write-Host "Failed! The path $dir_fullpath could not be created because the file $dir_path_test_exist exists."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Do you want to (A)re-enter (B)change to enter the full path to the folder? [A]|B"
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") { 
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 3
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } elseif ($dir_fullpath_value -eq 2) {
                        Write-Host "Invalid input! Please check the full path to the folder you want to use or create such as D:\myconfig."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Do you want to (A)re-enter (B)change to enter the full path to the folder? [A]|B"
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 3
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } elseif ($dir_fullpath_value -eq 0) {
                        Write-Host "Failed! Creating or using this path $dir_fullpath requires administrator privileges, which I have disabled for security reasons."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Do you want to (A)re-enter (B)change to enter the full path to the folder? [A]|B"
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") { 
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 3
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } elseif ($dir_fullpath -ceq $dir_path) {
                        Write-Host "Warning! The input is empty, $dir_path will be used directly as the storage folder."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you want to use this path, please save the files in the following folder in time:"
                        $dir_fullpath = $dir_fullpath.TrimEnd('\')
                        $files_preview = "$dir_fullpath\config\`n$dir_fullpath\config\yaml1\`n$dir_fullpath\config\yaml2\`n$dir_fullpath\config\yaml3\`n$dir_fullpath\tools\download\`n$dir_fullpath\tools\version\`n$dir_fullpath\tools\file\`n$dir_fullpath\tools\rule\`n$dir_fullpath\tools\tmp\"
                        $files_preview
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you have used this path before, the original saved files will not be affected, while the temporary files will be deleted."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Make sure there are no file paths that conflict with the folder paths above, e.g. the file D:\myconfig will conflict with the folder of the same name, D:\myconfig\ (note that Windows system filenames are not case-sensitive)."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If so, I will force the use or creation of these folders, and empty some of them."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Do you want to (A)use the path (B)re-enter? A|[B]"
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "A") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 0
                                    break
                                } elseif ($key.Key -eq "Enter" -or $key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A' or 'B[Enter]'."
                                }
                            }
                        }
                    } else {
                        Write-Host "The path $dir_fullpath you entered is valid."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you want to use this path, please save the files in the following folder in time:"
                        $dir_fullpath = $dir_fullpath.TrimEnd('\')
                        $files_preview = "$dir_fullpath\config\`n$dir_fullpath\config\yaml1\`n$dir_fullpath\config\yaml2\`n$dir_fullpath\config\yaml3\`n$dir_fullpath\tools\download\`n$dir_fullpath\tools\version\`n$dir_fullpath\tools\file\`n$dir_fullpath\tools\rule\`n$dir_fullpath\tools\tmp\"
                        $files_preview
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you have used this path before, the original saved files will not be affected, while the temporary files will be deleted."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Make sure there are no file paths that conflict with the folder paths above, e.g. the file D:\myconfig will conflict with the folder of the same name, D:\myconfig\ (note that Windows system filenames are not case-sensitive)."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If so, I will force the use or creation of these folders, and empty some of them."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Do you want to (A)use the path (B)re-enter (C)change to enter the full path to the folder? [A]|B|C"
                        if ($mode -eq 0) {
                            CapsLock_on
                            while ($True) {
                                if ([System.Console]::KeyAvailable) {
                                    $key = [System.Console]::ReadKey($True)
                                    if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                        Write-Host "Your choice: "$key.Key
                                        $path_value = 0
                                        break
                                    } elseif ($key.Key -eq "B") {
                                        Write-Host "Your choice: "$key.Key
                                        break
                                    } elseif ($key.Key -eq "C") {
                                        Write-Host "Your choice: "$key.Key
                                        $path_value = 3
                                        break
                                    } else {
                                        Write-Host "Invalid choice! Please select 'A[Enter]' or 'B' or 'C'."
                                    }
                                }
                            }
                        } else {
                            $path_value = 0
                        }
                    }
                    if ($path_value -ne 1) { break }
                }
                break
            } elseif ($dir_path_value -eq 0 -or $path_value -eq 3 -or ($path_value -eq 9 -and $key.Key -eq "B")) {
                if ($path_value -eq 9) { Write-Host "Your choice: "$key.Key }
                $path_value = 2
                while ($True) {
                    Write-Host "Please enter the full path to the folder you want to use or create such as D:\myconfig."
                    CapsLock_off
                    $dir_fullpath = (Read-Host).ToString() -creplace '[<>"|?*]', '' -creplace '/', '\' -creplace '^[\\\s]+|[\\\s]+$', '' -creplace '\s+\\', '\' -creplace '\\\s+', '\'
                    if ($dir_fullpath -match '^[a-zA-Z]:$') {
                        $dir_fullpath = ($dir_fullpath.Substring(0, 1).ToUpper() + $dir_fullpath.Substring(1)) + '\'
                    } elseif ($dir_fullpath -match '^[a-zA-Z]:\\') {
                        $dir_fullpath = ($dir_fullpath.Substring(0, 1).ToUpper() + $dir_fullpath.Substring(1)) -creplace ':', '' -creplace '^([A-Z])', '$1:' -creplace '\\+', '\'
                    } else {
                        $dir_fullpath = ""
                    }
                    $dir_disk = $dir_fullpath -creplace '^([A-Z]:\\).*$', '$1'
                    if ($dir_fullpath -and -not(Test-Path $dir_disk)) { $dir_fullpath = "" }
                    $dir_fullpath_value = 2
                    if ($dir_fullpath) {
                        $dir_fullpath_test = Join-Path -Path $dir_fullpath -ChildPath "test_test_test_test_test_test_test_test"
                        $dir_split_directories = $dir_fullpath_test -split "(?<=\\)" | Where-Object {$_ }
                        $dir_path_test = ""
                        $dir_path_test_name = ""
                        $dir_path_test_path = ""
                        $dir_path_test_real = ""
                        $dir_path_test_exist = ""
                        $dir_path_empty = ""
                        foreach ($dir_part in $dir_split_directories) {
                            if ($dir_path_test) {
                                $dir_path_test_name = $dir_part.TrimEnd('\')
                                $dir_path_test_path = $dir_path_test
                                $dir_path_test = Join-Path -Path $dir_path_test -ChildPath $dir_path_test_name
                            } else {
                                $dir_path_test_real = $dir_part
                                $dir_path_test = $dir_part
                            }
                            if ((Test-Path $dir_path_test) -and $dir_path_test_name) {
                                $dir_path_test_name = (Get-ChildItem $dir_path_test_path).Name | Where-Object {$_.ToUpper() -ceq $dir_path_test_name.ToUpper()}
                                if (Test-Path -PathType Leaf -Path $dir_path_test) {
                                    $dir_path_test_exist = Join-Path -Path $dir_path_test_real -ChildPath $dir_path_test_name
                                    $dir_fullpath_value = 3
                                }
                            } elseif (-not(Test-Path $dir_path_test) -and -not($dir_path_empty) -and $dir_fullpath_value -ne 3 ) {
                                $dir_path_empty = $dir_path_test
                                try {
                                    $null = New-Item -ItemType Directory -Path $dir_fullpath_test -ErrorAction Stop
                                    $dir_fullpath_value = 1
                                }
                                catch {
                                    $dir_fullpath_value = 0
                                }
                                if (Test-Path $dir_path_empty) { Remove-Item -Path $dir_path_empty -Force -Recurse }
                            }
                            $dir_path_test_real = Join-Path -Path $dir_path_test_real -ChildPath $dir_path_test_name
                        }
                        $dir_fullpath = $dir_path_test_real -creplace '([^:])\\test_test_test_test_test_test_test_test$', '$1' -creplace ':\\test_test_test_test_test_test_test_test$', ':\'
                    }
                    if ($dir_fullpath_value -eq 3) {
                        if ($dir_path_value -eq 1) {
                            Write-Host "Failed! The path $dir_fullpath could not be created because the file $dir_path_test_exist exists."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            Write-Host "Do you want to (A)re-enter (B)change to enter the name or path of the folder in ${dir_path}? [A]|B"
                        } else {
                            Write-Host "Failed! The path $dir_fullpath could not be created because the file $dir_path_test_exist exists. Please re-enter."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            continue
                        }
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 4
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } elseif ($dir_fullpath_value -eq 2) {
                        if ($dir_path_value -eq 1) {
                            Write-Host "Invalid input! Check the full path to the folder you want to use or create such as D:\myconfig."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            Write-Host "Do you want to (A)re-enter (B)change to enter the name or path of the folder in ${dir_path}? [A]|B"
                        } else {
                            Write-Host "Invalid input! Check the full path to the folder you want to use or create such as D:\myconfig. Please re-enter."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            continue
                        }
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 4
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } elseif ($dir_fullpath_value -eq 0) {
                        if ($dir_path_value -eq 1) {
                            Write-Host "Failed! Creating or using this path $dir_fullpath requires administrator privileges, which I have disabled for security reasons."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            Write-Host "Do you want to (A)re-enter (B)change to enter the name or path of the folder in ${dir_path}? [A]|B"
                        } else {
                            Write-Host "Failed! Creating or using this path $dir_fullpath requires administrator privileges, which I have disabled for security reasons. Please re-enter."
                            if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                            continue
                        }
                        CapsLock_on
                        while ($True) {
                            if ([System.Console]::KeyAvailable) {
                                $key = [System.Console]::ReadKey($True)
                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                    Write-Host "Your choice: "$key.Key
                                    break
                                } elseif ($key.Key -eq "B") {
                                    Write-Host "Your choice: "$key.Key
                                    $path_value = 4
                                    break
                                } else {
                                    Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                }
                            }
                        }
                    } else {
                        Write-Host "The path $dir_fullpath you entered is valid."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you want to use this path, please save the files in the following folder in time:"
                        $dir_fullpath = $dir_fullpath.TrimEnd('\')
                        $files_preview = "$dir_fullpath\config\`n$dir_fullpath\config\yaml1\`n$dir_fullpath\config\yaml2\`n$dir_fullpath\config\yaml3\`n$dir_fullpath\tools\download\`n$dir_fullpath\tools\version\`n$dir_fullpath\tools\file\`n$dir_fullpath\tools\rule\`n$dir_fullpath\tools\tmp\"
                        $files_preview
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If you have used this path before, the original saved files will not be affected, while the temporary files will be deleted."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "Make sure there are no file paths that conflict with the folder paths above, e.g. the file D:\myconfig will conflict with the folder of the same name, D:\myconfig\ (note that Windows system filenames are not case-sensitive)."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        Write-Host "If so, I will force the use or creation of these folders, and empty some of them."
                        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                        if ($dir_path_value -eq 1) {
                            Write-Host "Do you want to (A)use the path (B)re-enter (C)change to enter the name or path of the folder in ${dir_path}? [A]|B|C"
                        } else {
                            Write-Host "Do you want to (A)use the path (B)re-enter? [A]|B"
                        }
                        if ($mode -eq 0) {
                            CapsLock_on
                            while ($True) {
                                if ([System.Console]::KeyAvailable) {
                                    $key = [System.Console]::ReadKey($True)
                                    if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                        Write-Host "Your choice: "$key.Key
                                        $path_value = 0
                                        break
                                    } elseif ($key.Key -eq "B") {
                                        Write-Host "Your choice: "$key.Key
                                        break
                                    } elseif ($key.Key -eq "C" -and $dir_path_value -eq 1) {
                                        Write-Host "Your choice: "$key.Key
                                        $path_value = 4
                                        break
                                    } else {
                                        if ($dir_path_value -eq 1) {
                                            Write-Host "Invalid choice! Please select 'A[Enter]' or 'B' or 'C'."
                                        } else {
                                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                        }
                                    }
                                }
                            }
                        } else {
                            $path_value = 0
                        }
                    }
                    if ($path_value -ne 2) { break }
                }
                break
            } else {
                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
            }
        }
    }
    if ($path_value -eq 0) { break }
}

if (-not(Test-Path -PathType Container -Path "$dir_fullpath\config")) {
    if (Test-Path "$dir_fullpath\config") { Remove-Item -Path "$dir_fullpath\config" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\config" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\config\yaml1")) {
    if (Test-Path "$dir_fullpath\config\yaml1") { Remove-Item -Path "$dir_fullpath\config\yaml1" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\config\yaml1" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\config\yaml2")) {
    if (Test-Path "$dir_fullpath\config\yaml2") { Remove-Item -Path "$dir_fullpath\config\yaml2" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\config\yaml2" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\config\yaml3")) {
    if (Test-Path "$dir_fullpath\config\yaml3") { Remove-Item -Path "$dir_fullpath\config\yaml3" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\config\yaml3" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools")) {
    if (Test-Path "$dir_fullpath\tools") { Remove-Item -Path "$dir_fullpath\tools" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\download")) {
    if (Test-Path "$dir_fullpath\tools\download") { Remove-Item -Path "$dir_fullpath\tools\download" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\download" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\version")) {
    if (Test-Path "$dir_fullpath\tools\version") { Remove-Item -Path "$dir_fullpath\tools\version" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\version" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\file")) {
    if (Test-Path "$dir_fullpath\tools\file") { Remove-Item -Path "$dir_fullpath\tools\file" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\file" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\rule")) {
    if (Test-Path "$dir_fullpath\tools\rule") { Remove-Item -Path "$dir_fullpath\tools\rule" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\rule" | Out-Null
}
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\tmp")) {
    if (Test-Path "$dir_fullpath\tools\tmp") { Remove-Item -Path "$dir_fullpath\tools\tmp" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\tmp" | Out-Null
}
$clash = "$dir_fullpath\tools\tmp\process_hidden_clash.exe"
$subconverter = "$dir_fullpath\tools\tmp\process_hidden_subconverter.exe"
$curl = "$dir_fullpath\tools\tmp\process_hidden_curl.exe"
Write-Host "Directory $dir_fullpath will be used to store files."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }

while ($True) {
    if ($mode -eq 1) { break }
    if ((Test-Path $dir_fullpath\tools\file\clash-$arch1.exe) -and (Test-Path $dir_fullpath\tools\version\clash.version)) {
        Write-Host "Clash already exists!"
        Start-Sleep -Seconds 1
        $tag1 = (Get-Content "$dir_fullpath\tools\version\clash.version" -Encoding UTF8).ToString().Trim()
        Write-Host "Clash.version: $tag1"
        try { $tag1_update = (Invoke-RestMethod -Uri "https://api.github.com/repos/Dreamacro/clash/releases/latest" -TimeoutSec $time_s2 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
        if ($tag1_update -and $tag1_update -ne $tag1) {
            Write-Host "Detected an available update (version: $tag1_update)! Do you want to delete the current file and download the update with the source url? [Y]|N"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        Remove-Item -Path $dir_fullpath\tools\version\clash.version -Force
                        break
                    } elseif ($key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") { continue }
        }
        break
    } else {
        if (Test-Path $dir_fullpath\tools\file\clash-$arch1.exe) { Remove-Item -Path $dir_fullpath\tools\file\clash-$arch1.exe -Force }
        Remove-Item -Path $dir_fullpath\tools\download\clash* -Force
        if (Test-Path $dir_fullpath\tools\version\clash.version) { Remove-Item -Path $dir_fullpath\tools\version\clash.version -Force }
        Write-Host "Clash doesn't exist! Please go to (Source)https://github.com/Dreamacro/clash/releases/ or (Backup)https://github.com/thuhollow2/other/tree/main/ to download and extract the latest clash-$arch1.zip to the folder $dir_fullpath\tools\file."
        Start-Sleep -Seconds 1
        Write-Host "And create $dir_fullpath\tools\version\clash.version which is recommended for recording version information."
        Start-Sleep -Seconds 1
        Write-Host "Do you want to download and extract them automatically? [Y]|N"
        CapsLock_on
        while ($True) {
            if ([System.Console]::KeyAvailable) {
                $key = [System.Console]::ReadKey($True)
                if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "Please select a repository to download clash: [Source]|Backup. [A]|B"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            $tag1 = ""
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Downloading clash! Please wait until the end of the process."
                                try { $tag1 = (Invoke-RestMethod -Uri "https://api.github.com/repos/Dreamacro/clash/releases/latest" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
                                if ($tag1) {
                                    $tag1 | Out-File "$dir_fullpath\tools\version\clash.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://github.com/Dreamacro/clash/releases/download/$tag1/clash-$arch1-$tag1.zip" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\clash-$arch1-$tag1.zip" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\clash-$arch1-$tag1.zip) { Expand-Archive -Path "$dir_fullpath\tools\download\clash-$arch1-$tag1.zip" -DestinationPath "$dir_fullpath\tools\file" -Force }
                                if (-not(Test-Path $dir_fullpath\tools\file\clash-$arch1.exe) -or -not(Test-Path $dir_fullpath\tools\version\clash.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } elseif ($key.Key -eq "B") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Downloading clash! Please wait until the end of the process."
                                try { $tag1 = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/clash.version" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).ToString().Trim() } catch {}
                                if ($tag1) {
                                    $tag1 | Out-File "$dir_fullpath\tools\version\clash.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/clash-$arch1.zip" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\clash-$arch1.zip" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\clash-$arch1.zip) { Expand-Archive -Path "$dir_fullpath\tools\download\clash-$arch1.zip" -DestinationPath "$dir_fullpath\tools\file" -Force }
                                if (-not(Test-Path $dir_fullpath\tools\file\clash-$arch1.exe) -or -not(Test-Path $dir_fullpath\tools\version\clash.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                            }
                        }
                    }
                    break
                } elseif ($key.Key -eq "N") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "If you want to download it manually, extract clash-$arch1-$tag1.zip completely to $dir_fullpath\tools\file to make sure that clash-$arch1.exe is located at $dir_fullpath\tools\file and create $dir_fullpath\tools\version\clash.version which is recommended for recording version information."
                    Start-Sleep -Seconds 1
                    Write-Host "Press any key to exit the program!"
                    $key = [System.Console]::ReadKey($True)
                    exit
                } else {
                    Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                }
            }
        }
    }
}

while ($True) {
    if ($mode -eq 1) { break }
    if ((Test-Path $dir_fullpath\tools\file\Country.mmdb) -and (Test-Path $dir_fullpath\tools\version\Country.mmdb.version)) {
        Write-Host "Country.mmdb already exists!"
        Start-Sleep -Seconds 1
        $tag2 = (Get-Content "$dir_fullpath\tools\version\Country.mmdb.version" -Encoding UTF8).ToString().Trim()
        Write-Host "Country.mmdb.version: $tag2"
        try { $tag2_update = (Invoke-RestMethod -Uri "https://api.github.com/repos/alecthw/mmdb_china_ip_list/releases/latest" -TimeoutSec $time_s2 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
        if ($tag2_update -and $tag2_update -ne $tag2) {
            Write-Host "Detected an available update (version: $tag2_update)! Do you want to delete the current file and download the update with the source url? [Y]|N"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        Remove-Item -Path $dir_fullpath\tools\version\Country.mmdb.version -Force
                        break
                    } elseif ($key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") { continue }
        }
        break
    } else {
        if (Test-Path $dir_fullpath\tools\file\Country.mmdb) { Remove-Item -Path $dir_fullpath\tools\file\Country.mmdb -Force }
        if (Test-Path $dir_fullpath\tools\download\Country.mmdb) { Remove-Item -Path $dir_fullpath\tools\download\Country.mmdb -Force }
        if (Test-Path $dir_fullpath\tools\version\Country.mmdb.version) { Remove-Item -Path $dir_fullpath\tools\version\Country.mmdb.version -Force }
        Write-Host "Country.mmdb doesn't exist! Please go to (Source)https://github.com/alecthw/mmdb_china_ip_list/releases/ or (Backup)https://github.com/thuhollow2/other/tree/main/ to download the latest Country.mmdb to the folder $dir_fullpath\tools\file."
        Start-Sleep -Seconds 1
        Write-Host "And create $dir_fullpath\tools\version\Country.mmdb.version which is recommended for recording version information."
        Start-Sleep -Seconds 1
        Write-Host "Do you want to download them automatically? [Y]|N"
        CapsLock_on
        while ($True) {
            if ([System.Console]::KeyAvailable) {
                $key = [System.Console]::ReadKey($True)
                if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "Please select a repository to download Country.mmdb: [Source]|Backup. [A]|B"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            $tag2 = ""
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Downloading Country.mmdb! Please wait until the end of the process."
                                try { $tag2 = (Invoke-RestMethod -Uri "https://api.github.com/repos/alecthw/mmdb_china_ip_list/releases/latest" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
                                if ($tag2) {
                                    $tag2 | Out-File "$dir_fullpath\tools\version\Country.mmdb.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://github.com/alecthw/mmdb_china_ip_list/releases/download/$tag2/Country.mmdb" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\Country.mmdb" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\Country.mmdb) { Copy-Item $dir_fullpath\tools\download\Country.mmdb $dir_fullpath\tools\file\Country.mmdb }
                                if (-not(Test-Path $dir_fullpath\tools\file\Country.mmdb) -or -not(Test-Path $dir_fullpath\tools\version\Country.mmdb.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } elseif ($key.Key -eq "B") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Downloading Country.mmdb! Please wait until the end of the process."
                                try { $tag2 = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/Country.mmdb.version" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).ToString().Trim() } catch {}
                                if ($tag2) {
                                    $tag2 | Out-File "$dir_fullpath\tools\version\Country.mmdb.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/Country.mmdb" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\Country.mmdb" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\Country.mmdb) { Copy-Item $dir_fullpath\tools\download\Country.mmdb $dir_fullpath\tools\file\Country.mmdb }
                                if (-not(Test-Path $dir_fullpath\tools\file\Country.mmdb) -or -not(Test-Path $dir_fullpath\tools\version\Country.mmdb.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                            }
                        }
                    }
                    break
                } elseif ($key.Key -eq "N") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "If you want to download it manually, move Country.mmdb to $dir_fullpath\tools\file to make sure Country.mmdb is located at $dir_fullpath\tools\file and create $dir_fullpath\tools\version\Country.mmdb.version which is recommended for recording version information."
                    Start-Sleep -Seconds 1
                    Write-Host "Press any key to exit the program!"
                    $key = [System.Console]::ReadKey($True)
                    exit
                } else {
                    Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                }
            }
        }
    }
}

while ($True) {
    if ($mode -eq 1) { break }
    if ((Test-Path $dir_fullpath\tools\file\subconverter.exe) -and (Test-Path $dir_fullpath\tools\version\subconverter.version)) {
        if (Test-Path $dir_fullpath\tools\file\subconverter) { Remove-Item -Path "$dir_fullpath\tools\file\subconverter" -Force -Recurse }
        Write-Host "Subconverter already exists!"
        Start-Sleep -Seconds 1
        $tag3 = (Get-Content "$dir_fullpath\tools\version\subconverter.version" -Encoding UTF8).ToString().Trim()
        Write-Host "Subconverter.version: $tag3"
        try { $tag3_update = (Invoke-RestMethod -Uri "https://api.github.com/repos/tindy2013/subconverter/releases/latest" -TimeoutSec $time_s2 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
        if ($tag3_update -and $tag3_update -ne $tag3) {
            Write-Host "Detected an available update (version: $tag3_update)! Do you want to delete the current file and download the update with the source url? [Y]|N"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        Remove-Item -Path $dir_fullpath\tools\version\subconverter.version -Force
                        break
                    } elseif ($key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") { continue }
        }
        break
    } else {
        if (Test-Path $dir_fullpath\tools\file\subconverter.exe) { Remove-Item -Path $dir_fullpath\tools\file\subconverter.exe -Force }
        Remove-Item -Path $dir_fullpath\tools\download\subconverter* -Force
        if (Test-Path $dir_fullpath\tools\version\subconverter.version) { Remove-Item -Path $dir_fullpath\tools\version\subconverter.version -Force }
        Write-Host "Subconverter doesn't exist! Please go to (Source)https://github.com/tindy2013/subconverter/releases/ to download and extract the latest subconverter_$arch2.7z or (Backup)https://github.com/thuhollow2/other/tree/main/ to download and extract the latest subconverter_$arch2.zip to the folder $dir_fullpath\tools\file."
        Start-Sleep -Seconds 1
        Write-Host "And create $dir_fullpath\tools\version\subconverter.version which is recommended for recording version information."
        Start-Sleep -Seconds 1
        Write-Host "Do you want to download and extract them automatically? (For the source, you may need to install Module 7Zip4Powershell to extract the 7z archive.) [Y]|N"
        CapsLock_on
        while ($True) {
            if ([System.Console]::KeyAvailable) {
                $key = [System.Console]::ReadKey($True)
                if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "Please select a repository to download subconverter: [Source]|Backup. [A]|B"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            $tag3 = ""
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                Write-Host "Your choice: "$key.Key
                                while ($True) {
                                    if (-not(Get-Module -Name 7Zip4Powershell -ListAvailable)) {
                                        Write-Host "Module 7Zip4Powershell is not installed! Do you want to install it with administrator rights? [Y]|N"
                                        CapsLock_on
                                        while ($True) {
                                            if ([System.Console]::KeyAvailable) {
                                                $key = [System.Console]::ReadKey($True)
                                                if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                                                    Write-Host "Your choice: "$key.Key
                                                    Write-Host "Please allow Windows PowerShell to make changes to install Module 7Zip4Powershell and wait for the new window to close. Press 'Enter' to start."
                                                    Read-Host
                                                    Start-Process powershell -Verb RunAs -Wait -ArgumentList "-Command Install-Module -Name 7Zip4Powershell -Force"
                                                    if (-not(Get-Module -Name 7Zip4Powershell -ListAvailable)) {
                                                        Write-Host "Failed to install! If the installation of Module 7Zip4Powershell always fails, please choose (Backup) to download and extract the latest subconverter_$arch2.zip automatically or do it manually via (Source) or (Backup) url."
                                                        Start-Sleep -Seconds 1
                                                    }
                                                    break
                                                } elseif ($key.Key -eq "N") {
                                                    Write-Host "Your choice: "$key.Key
                                                    Write-Host "If the installation of Module 7Zip4Powershell always fails, please choose (Backup) to download and extract the latest subconverter_$arch2.zip automatically or do it manually via (Source) or (Backup) url."
                                                    Start-Sleep -Seconds 1
                                                    break
                                                } else {
                                                    Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                                                }
                                            }
                                        }
                                        if ($key.Key -eq "N") { break }
                                    } else {
                                        Write-Host "Module 7Zip4Powershell is already installed!"
                                        Start-Sleep -Seconds 1
                                        break
                                    }
                                }
                                if (-not(Get-Module -Name 7Zip4Powershell -ListAvailable)) { break }
                                Write-Host "Downloading subconverter! Please wait until the end of the process."
                                try { $tag3 = (Invoke-RestMethod -Uri "https://api.github.com/repos/tindy2013/subconverter/releases/latest" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).tag_name.ToString().Trim() } catch {}
                                if ($tag3) {
                                    $tag3 | Out-File "$dir_fullpath\tools\version\subconverter.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://github.com/tindy2013/subconverter/releases/download/$tag3/subconverter_$arch2.7z" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\subconverter_$arch2.7z" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\subconverter_$arch2.7z) {
                                    Expand-7Zip -ArchiveFileName "$dir_fullpath\tools\download\subconverter_$arch2.7z" -TargetPath "$dir_fullpath\tools\file"
                                    Copy-Item $dir_fullpath\tools\file\subconverter\subconverter.exe $dir_fullpath\tools\file\subconverter.exe
                                }
                                if (-not(Test-Path $dir_fullpath\tools\file\subconverter.exe) -or -not(Test-Path $dir_fullpath\tools\version\subconverter.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } elseif ($key.Key -eq "B") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Downloading subconverter! Please wait until the end of the process."
                                try { $tag3 = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/subconverter.version" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).ToString().Trim() } catch {}
                                if ($tag3) {
                                    $tag3 | Out-File "$dir_fullpath\tools\version\subconverter.version" -Encoding UTF8
                                } else {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                    break
                                }
                                try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/subconverter_$arch2.zip" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\subconverter_$arch2.zip" } catch {}
                                if (Test-Path $dir_fullpath\tools\download\subconverter_$arch2.zip) {
                                    Expand-Archive -Path "$dir_fullpath\tools\download\subconverter_$arch2.zip" -DestinationPath "$dir_fullpath\tools\file" -Force
                                    Copy-Item $dir_fullpath\tools\file\subconverter\subconverter.exe $dir_fullpath\tools\file\subconverter.exe
                                }
                                if (-not(Test-Path $dir_fullpath\tools\file\subconverter.exe) -or -not(Test-Path $dir_fullpath\tools\version\subconverter.version)) {
                                    Write-Host "Failed to download! Please check the network."
                                    Start-Sleep -Seconds 1
                                }
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                            }
                        }
                    }
                    break
                } elseif ($key.Key -eq "N") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "If you have already downloaded it manually, extract subconverter_$arch2.7z or subconverter_$arch2.zip completely to $dir_fullpath\tools\file to make sure that subconverter.exe is located at $dir_fullpath\tools\file and create $dir_fullpath\tools\version\subconverter.version which is recommended for recording version information."
                    Start-Sleep -Seconds 1
                    Write-Host "Press any key to exit the program!"
                    $key = [System.Console]::ReadKey($True)
                    exit
                } else {
                    Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                }
            }
        }
    }
}

while ($True) {
    if ($mode -eq 1) { break }
    if ((Test-Path $dir_fullpath\tools\file\OpenAI.ini) -and (Test-Path $dir_fullpath\tools\version\rules.version)) {
        $rule_list_value = 1
        $rule_list = ((Get-Content "$dir_fullpath\tools\file\OpenAI.ini" -Encoding UTF8 | Where-Object {$_ -match '^ruleset=.*,\s*[^\s]*\.list$'}) -creplace '^ruleset=.*,\s*([^\s]*\.list)$', '$1') -split "`r?`n"
        for ($i = 0; $i -lt $rule_list.Count; $i++) {
            $line = $rule_list[$i]
            if (-not(Test-Path "$dir_fullpath\tools\rule\$line") -or -not(Get-Content "$dir_fullpath\tools\rule\$line" -Encoding UTF8 | Where-Object {$_}) ) {
                $rule_list_value = 0
            }
        }
    } else {
        $rule_list_value = 0
    }
    if ($rule_list_value -eq 1) {
        Write-Host "Rules already exist!"
        Start-Sleep -Seconds 1
        $tag4 = (Get-Content "$dir_fullpath\tools\version\rules.version" -Encoding UTF8).ToString().Trim()
        Write-Host "Rules.version: $tag4"
        try { $tag4_update = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/thuhollow2/rule/main/Clash/rules.version" -TimeoutSec $time_s2 -MaximumRedirection $max_redirection).ToString().Trim() } catch {}
        if ($tag4_update -and $tag4_update -ne $tag4) {
            Write-Host "Detected an available update (version: $tag4_update)! Do you want to delete the current file and download the update? [Y]|N"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        Remove-Item -Path $dir_fullpath\tools\version\rules.version -Force
                        break
                    } elseif ($key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") { continue }
        }
        break
    } else {
        if (Test-Path $dir_fullpath\tools\file\OpenAI.ini) { Remove-Item -Path $dir_fullpath\tools\file\OpenAI.ini -Force }
        if (Test-Path $dir_fullpath\tools\version\rules.version) { Remove-Item -Path $dir_fullpath\tools\version\rules.version -Force }
        Remove-Item -Path $dir_fullpath\tools\rule\* -Force
        Write-Host "Rules don't exist! Please go to https://github.com/thuhollow2/other/tree/main/ to download OpenAI.ini to $dir_fullpath\tools\file and go to https://github.com/thuhollow2/rule/tree/main/ to download the latest rules which the OpenAI.ini lists to the folder $dir_fullpath\tools\rule."
        Start-Sleep -Seconds 1
        Write-Host "And create $dir_fullpath\tools\version\rules.version which is recommended for recording version information."
        Start-Sleep -Seconds 1
        Write-Host "Do you want to download them automatically? [Y]|N"
        CapsLock_on
        while ($True) {
            if ([System.Console]::KeyAvailable) {
                $key = [System.Console]::ReadKey($True)
                if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "Downloading rules! Please wait until the end of the process."
                    try { $tag4 = (Invoke-RestMethod -Uri "https://raw.githubusercontent.com/thuhollow2/rule/main/Clash/rules.version" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection).ToString().Trim() } catch {}
                    if ($tag4) {
                        $tag4 | Out-File "$dir_fullpath\tools\version\rules.version" -Encoding UTF8
                    } else {
                        Write-Host "Failed to download! Please check the network."
                        Start-Sleep -Seconds 1
                        break
                    }
                    try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thuhollow2/other/main/OpenAI.ini" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\OpenAI.ini" } catch {}
                    if (Test-Path $dir_fullpath\tools\download\OpenAI.ini) { Copy-Item $dir_fullpath\tools\download\OpenAI.ini $dir_fullpath\tools\file\OpenAI.ini }
                    if ((Test-Path $dir_fullpath\tools\file\OpenAI.ini) -and (Test-Path $dir_fullpath\tools\version\rules.version)) {
                        $rule_list = ((Get-Content "$dir_fullpath\tools\file\OpenAI.ini" -Encoding UTF8 | Where-Object {$_ -match '^ruleset=.*,\s*[^\s]*\.list$'}) -creplace '^ruleset=.*,\s*([^\s]*\.list)$', '$1') -split "`r?`n"
                        for ($i = 0; $i -lt $rule_list.Count; $i++) {
                            $line = $rule_list[$i]
                            try { Invoke-WebRequest -Uri "https://raw.githubusercontent.com/thuhollow2/rule/main/Clash/$line" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\download\$line" } catch {}
                            if (Test-Path $dir_fullpath\tools\download\$line) {
                                Copy-Item "$dir_fullpath\tools\download\$line" "$dir_fullpath\tools\rule\$line"
                            } else {
                                Write-Host "Failed to download! Please check the network."
                                Start-Sleep -Seconds 1
                                break
                            }
                        }
                    }
                    break
                } elseif ($key.Key -eq "N") {
                    Write-Host "Your choice: "$key.Key
                    Write-Host "If you want to download it manually, move OpenAI.ini to $dir_fullpath\tools\file to make sure that OpenAI.ini is located at $dir_fullpath\tools\file, move rules to to the folder $dir_fullpath\tools\rule and create $dir_fullpath\tools\version\rules.version which is recommended for recording version information."
                    Start-Sleep -Seconds 1
                    Write-Host "Press any key to exit the program!"
                    $key = [System.Console]::ReadKey($True)
                    exit
                } else {
                    Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                }
            }
        }
    }
}

Write-Host "Part II: <$esc[32mDownload and Examine Subscription Files$esc[0m>"
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
Write-Host "You can download and move your subscription file to $dir_fullpath\config\yaml1 as the local file to test."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
Write-Host "You can also use a subscription url to download automatically it through this program."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
while ($True) {
    Remove-Item -Path "$dir_fullpath\tools\tmp\*" -Force -Recurse
    Copy-Item $dir_fullpath\tools\file\clash-$arch1.exe $clash
    Copy-Item $dir_fullpath\tools\file\Country.mmdb $dir_fullpath\tools\tmp\Country.mmdb
    Copy-Item $dir_fullpath\tools\file\subconverter.exe $subconverter
    Copy-Item $((Get-Command -Name curl.exe).Source) $dir_fullpath\tools\tmp\process_hidden_curl.exe
    Copy-Item $dir_fullpath\tools\file\OpenAI.ini $dir_fullpath\tools\tmp\OpenAI.ini
    Copy-Item $dir_fullpath\tools\rule\*.list $dir_fullpath\tools\tmp\
    Remove-Item -Path "$dir_fullpath\config\yaml2\*" -Force -Recurse
    Remove-Item -Path "$dir_fullpath\config\yaml3\*" -Force -Recurse

    if ($mode -eq 0) {
        $local_file = Get-ChildItem -Path "$dir_fullpath\config\yaml1" -File | Select-Object -ExpandProperty Name
        if ($local_file) {
            $local_file_content = Get-Content "$dir_fullpath\config\yaml1\*" -Encoding UTF8 | Where-Object {$_ }
        } else {
            $local_file_content = ""
        }
        if ($local_file_content) {
            $local_file = $local_file -split "`r?`n"
            $local_file_test = ""
            for ($i = 0; $i -lt $local_file.Count; $i++) {
                $local_single_file = $local_file[$i]
                if (Get-Content "$dir_fullpath\config\yaml1\$local_single_file" -Encoding UTF8 | Where-Object {$_ }) {
                    Copy-Item "$dir_fullpath\config\yaml1\$local_single_file" "$dir_fullpath\tools\tmp\a$($i + 1).yaml"
                    $local_file_test = $local_file_test + "`n" + $local_single_file
                }
            }
            $local_file_test = $local_file_test.TrimStart("`n")
            Write-Host "Detected the local subscription file in $dir_fullpath\config\yaml1:"
            $local_file_test
            Write-Host "Use it? [Y]|N"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        $file_value = 9
                        break
                    } elseif ($key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        $file_value = 8
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            while ($True) {
                if ( $file_value -eq 8 ) {
                    Write-Host "Are you sure not to use the local subscription file in $dir_fullpath\config\yaml1? [Y]|N"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 8
                                Remove-Item -Path "$dir_fullpath\tools\tmp\a*.yaml" -Force -Recurse
                                break
                            } elseif ($key.Key -eq "N") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 9
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                            }
                        }
                    }
                    if ( $file_value -eq 8 ) { break }
                } else {
                    Write-Host "Are you sure to use the local subscription file in $dir_fullpath\config\yaml1 instead of downloading via the subscription url? [Y]|N"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 9
                                break
                            } elseif ($key.Key -eq "N") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 8
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                            }
                        }
                    }
                    if ( $file_value -eq 9 ) { break }
                }
            }
        } else {
            $file_value = 8
        }
    }
    if ($mode -eq 1 -or $file_value -eq 8) {
        if ($mode -eq 0 -and -not($local_file_content)) {
            Write-Host "There is no file in $dir_fullpath\config\yaml1; if you have just moved files to $dir_fullpath\config\yaml1, you can re-test to see if any local files exist. Y|[N]"
            CapsLock_on
            while ($True) {
                if ([System.Console]::KeyAvailable) {
                    $key = [System.Console]::ReadKey($True)
                    if ($key.Key -eq "Y") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } elseif ($key.Key -eq "Enter" -or $key.Key -eq "N") {
                        Write-Host "Your choice: "$key.Key
                        break
                    } else {
                        Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                    }
                }
            }
            if ($key.Key -eq "Y") { continue }
        }
        Write-Host "You can download the subscription file using subscription urls, such as https://www.baidu.com/myconfig.txt, ftp://192.168.1.1/myconfig.log, D:\myconfig\myconfig.yaml (so it can be a local Windows file in another location)."
        if ($mode -eq 0) { Start-Sleep -Seconds 1 }
        while ($True) {
            if ($mode -eq 0) {
                $file_value = 1
                if (Test-Path "$dir_fullpath\tools\file\url.txt") {
                    $local_url_content = Get-Content "$dir_fullpath\tools\file\url.txt" -Encoding UTF8 | Where-Object {$_ }
                } else {
                    $local_url_content = ""
                }
                if ($local_url_content) {
                    Write-Host "Detected local subscription urls in $dir_fullpath\tools\file\url.txt:"
                    $lines = $local_url_content -split "`r?`n"
                    $processed = @()
                    foreach ($line in $lines) {
                        if($line.ToString().Trim()) {
                            $processed += $line.ToString().Trim() 
                        }
                    }
                    $processed -join [environment]::NewLine
                    Write-Host "Use it? [Y]|N"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 2
                                break
                            } elseif ($key.Key -eq "N") {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 3
                                break
                            } else {
                                Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                            }
                        }
                    }
                }
                if ( $file_value -ne 2 ) {
                    if ( $file_value -eq 3 ) {
                        Write-Host "Warning! If you enter and save your own subscription urls, the original saved urls in the configuration file $dir_fullpath\tools\file\url.txt will be overwritten!"
                        Start-Sleep -Seconds 1
                        Write-Host "Do you want to (A)use your own subscription urls (B)use the public url I provided (only for test):"
                        $my_url
                        Write-Host "(C)re-select the urls? A|B|[C]"
                    } else {
                        Write-Host "Do you want to use (A)your own subscription urls (B)the public url I provided (only for test):"
                        $my_url
                        Write-Host "? [A]|B"
                    }
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            if ((($key.Key -eq "Enter" -or $key.Key -eq "A") -and $file_value -ne 3) -or ($key.Key -eq "A" -and $file_value -eq 3)) {
                                Write-Host "Your choice: "$key.Key
                                while ($True) {
                                    Write-Host "Please enter your subscription urls!"
                                    Start-Sleep -Seconds 1
                                    $i = 1
                                    $url_list = @()
                                    while ($True) {
                                        Write-Host "Url ${i}: (Pressing 'Enter' will end the url input.)"
                                        CapsLock_off
                                        $url = (Read-Host).ToString().Trim()
                                        if ($url) {
                                            $url_fullpath = $url -creplace '[<>"|?*]', '' -creplace '/', '\' -creplace '^[\\\s]+|[\\\s]+$', '' -creplace '\s+\\', '\' -creplace '\\\s+', '\'
                                            if ($url_fullpath -match '^[a-zA-Z]:$') {
                                                $url_fullpath = ($url_fullpath.Substring(0, 1).ToUpper() + $url_fullpath.Substring(1)) + '\'
                                            } elseif ($url_fullpath -match '^[a-zA-Z]:\\') {
                                                $url_fullpath = ($url_fullpath.Substring(0, 1).ToUpper() + $url_fullpath.Substring(1)) -creplace ':', '' -creplace '^([A-Z])', '$1:' -creplace '\\+', '\'
                                            } else {
                                                $url_fullpath = ""
                                            }
                                            if ($url_fullpath -and -not(Test-Path -PathType Leaf -Path $url_fullpath)) { $url_fullpath = "" }
                                            if ($url_fullpath) {
                                                $url_fullpath_test = Join-Path -Path $url_fullpath -ChildPath "test_test_test_test_test_test_test_test"
                                                $url_split_directories = $url_fullpath_test -split "(?<=\\)" | Where-Object {$_ }
                                                $url_path_test = ""
                                                $url_path_test_name = ""
                                                $url_path_test_path = ""
                                                $url_path_test_real = ""
                                                foreach ($url_part in $url_split_directories) {
                                                    if ($url_path_test) {
                                                        $url_path_test_name = $url_part.TrimEnd('\')
                                                        $url_path_test_path = $url_path_test
                                                        $url_path_test = Join-Path -Path $url_path_test -ChildPath $url_path_test_name
                                                    } else {
                                                        $url_path_test_real = $url_part
                                                        $url_path_test = $url_part
                                                    }
                                                    if ((Test-Path $url_path_test) -and $url_path_test_name) {
                                                        $url_path_test_name = (Get-ChildItem $url_path_test_path).Name | Where-Object {$_.ToUpper() -ceq $url_path_test_name.ToUpper()}
                                                    }
                                                    $url_path_test_real = Join-Path -Path $url_path_test_real -ChildPath $url_path_test_name
                                                }
                                                $url = $url_path_test_real -creplace '([^:])\\test_test_test_test_test_test_test_test$', '$1' -creplace ':\\test_test_test_test_test_test_test_test$', ':\'
                                            } elseif ($url.ToLower() -match '^http://') {
                                                $url = $url -creplace '^([^:])*://', 'http://'
                                            } elseif ($url.ToLower() -match '^https://') {
                                                $url = $url -creplace '^([^:])*://', 'https://'
                                            } elseif ($url.ToLower() -match '^ftp://') {
                                                $url = $url -creplace '^([^:])*://', 'ftp://'
                                            } else {
                                                $url = ""
                                            }
                                            if (-not($url)){
                                                Write-Host "Invalid input! Please re-enter."
                                                continue
                                            }
                                        } else {
                                            if ( $i -eq 1 ){
                                                Write-Host "Total input is null! Please re-enter."
                                                Start-Sleep -Seconds 1
                                                Write-Host "Do you want to (A)re-enter the urls (B)re-select urls? [A]|B"
                                                CapsLock_on
                                                while ($True) {
                                                    if ([System.Console]::KeyAvailable) {
                                                        $key = [System.Console]::ReadKey($True)
                                                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                                            Write-Host "Your choice: "$key.Key
                                                            break
                                                        } elseif ($key.Key -eq "B") {
                                                            Write-Host "Your choice: "$key.Key
                                                            break
                                                        } else {
                                                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                                        }
                                                    }
                                                }
                                                if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                                    continue
                                                } else {
                                                    break
                                                }
                                            } else {
                                                break
                                            }
                                        }
                                        $url_list = $url_list + $url
                                        Write-Host "Url ${i}: $url"
                                        Start-Sleep -Seconds 1
                                        $i++
                                    }
                                    if (-not($url_list)) { break }
                                    Write-Host "The urls you have entered:"
                                    $url_list
                                    Start-Sleep -Seconds 1
                                    Write-Host "Do you want to (A)use the urls (B)re-enter the urls (C)re-select urls? [A]|B|C"
                                    CapsLock_on
                                    while ($True) {
                                        if ([System.Console]::KeyAvailable) {
                                            $key = [System.Console]::ReadKey($True)
                                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                                Write-Host "Your choice: "$key.Key
                                                break
                                            } elseif ($key.Key -eq "B") {
                                                Write-Host "Your choice: "$key.Key
                                                break
                                            } elseif ($key.Key -eq "C") {
                                                Write-Host "Your choice: "$key.Key
                                                break
                                            } else {
                                                Write-Host "Invalid choice! Please select 'A[Enter]' or 'B' or 'C'."
                                            }
                                        }
                                    }
                                    if ($key.Key -eq "Enter" -or $key.Key -eq "A" -or $key.Key -eq "C") { break }
                                }
                                if ( -not($url_list) -or $key.Key -eq "C" ) {
                                    $file_value = 6
                                    break
                                }
                                Write-Host "Do you want to save the urls in $dir_fullpath\tools\file\url.txt? [Y]|N"
                                CapsLock_on
                                while ($True) {
                                    if ([System.Console]::KeyAvailable) {
                                        $key = [System.Console]::ReadKey($True)
                                        if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                                            Write-Host "Your choice: "$key.Key
                                            while ($True) {
                                                Write-Host "Please set simple names for your urls."
                                                Start-Sleep -Seconds 1
                                                $url_name_list = @()
                                                $url_list = $url_list -split "`r?`n"
                                                for ($i = 0; $i -lt $url_list.Count; $i++) {
                                                    while ($True) {
                                                        Write-Host "Name of url $($i + 1):"
                                                        CapsLock_off
                                                        $url_name = (Read-Host).ToString().Trim() -creplace '[<>]', ''
                                                        if ($url_name) {
                                                            Write-Host "Name of url $($i + 1): $url_name"
                                                            Start-Sleep -Seconds 1
                                                            $url_tmp = $url_list[$i]
                                                            $url_name = "<$url_name> $url_tmp"
                                                            $url_name_list = $url_name_list + $url_name
                                                            break
                                                        } else {
                                                            Write-Host "Invalid input! Please re-enter."
                                                        }
                                                    }
                                                }
                                                Write-Host "Names of the urls you have entered:"
                                                $url_name_list
                                                Start-Sleep -Seconds 1
                                                Write-Host "Do you want to (A)use the names (B)re-enter the names (C)give up saving urls? [A]|B|C"
                                                CapsLock_on
                                                while ($True) {
                                                    if ([System.Console]::KeyAvailable) {
                                                        $key = [System.Console]::ReadKey($True)
                                                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                                            Write-Host "Your choice: "$key.Key
                                                            break
                                                        } elseif ($key.Key -eq "B") {
                                                            Write-Host "Your choice: "$key.Key
                                                            break
                                                        } elseif ($key.Key -eq "C") {
                                                            Write-Host "Your choice: "$key.Key
                                                            break
                                                        } else {
                                                            Write-Host "Invalid choice! Please select 'A[Enter]' or 'B' or 'C'."
                                                        }
                                                    }
                                                }
                                                if ($key.Key -eq "Enter" -or $key.Key -eq "A" -or $key.Key -eq "C") { break }
                                            }
                                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                                $url_list = $url_name_list
                                                $url_list | Out-File "$dir_fullpath\tools\file\url.txt" -Encoding UTF8
                                                Write-Host "Your urls are saved in the path: $dir_fullpath\tools\file\url.txt"
                                                Start-Sleep -Seconds 1
                                            }
                                            break
                                        } elseif ($key.Key -eq "N") {
                                            Write-Host "Your choice: "$key.Key
                                            break
                                        } else {
                                            Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                                        }
                                    }
                                }
                                $file_value = 4
                                break
                            } elseif ($key.Key -eq "B") {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "The public urls:"
                                $url_list = $my_url
                                $url_list
                                Start-Sleep -Seconds 1
                                Write-Host "The public urls will not be saved to the configuration file $dir_fullpath\tools\file\url.txt"
                                Start-Sleep -Seconds 1
                                Write-Host "Do you want to (A)use the public url (B)re-select the urls? [A]|B"
                                CapsLock_on
                                while ($True) {
                                    if ([System.Console]::KeyAvailable) {
                                        $key = [System.Console]::ReadKey($True)
                                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                            Write-Host "Your choice: "$key.Key
                                            $file_value = 5
                                            break
                                        } elseif ($key.Key -eq "B") {
                                            Write-Host "Your choice: "$key.Key
                                            $file_value = 6
                                            break
                                        } else {
                                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                        }
                                    }
                                }
                                break
                            } elseif (($key.Key -eq "Enter" -or $key.Key -eq "C") -and $file_value -eq 3) {
                                Write-Host "Your choice: "$key.Key
                                $file_value = 6
                                break
                            } elseif ($file_value -eq 3) {
                                Write-Host "Your choice: "$key.Key
                                Write-Host "Invalid choice! Please select 'A' or 'B' or 'C[Enter]'."
                            } else {
                                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                            }
                        }
                    }
                }
                if ( $file_value -eq 6 ) { continue }
                Write-Host "Do you want to (A)continue to download files (B)re-select the urls? [A]|B"
                CapsLock_on
                while ($True) {
                    if ([System.Console]::KeyAvailable) {
                        $key = [System.Console]::ReadKey($True)
                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                            Write-Host "Your choice: "$key.Key
                            if ( $file_value -eq 2){
                                $lines = ((Get-Content "$dir_fullpath\tools\file\url.txt" -Encoding UTF8) | Where-Object {$_ }) -split "`r?`n"
                                $processed = @()
                                foreach ($line in $lines) {
                                    if($line.ToString().Trim()) {
                                        $processed += $line.ToString().Trim() 
                                    }
                                }
                                $url_list = $processed -join [environment]::NewLine
                                $url_list | Out-File "$dir_fullpath\tools\file\url.txt" -Encoding UTF8
                            }
                            $file_value = 7
                            break
                        } elseif ($key.Key -eq "B") {
                            Write-Host "Your choice: "$key.Key
                            break
                        } else {
                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                        }
                    }
                }
            }
            if ( $mode -eq 1 -or $file_value -eq 7 ) {
                if ($mode -eq 1){
                    if (Get-Content "$dir_fullpath\tools\file\url.txt" -Encoding UTF8 | Where-Object {$_ }) {
                        $url_list = Get-Content "$dir_fullpath\tools\file\url.txt" -Encoding UTF8 | Where-Object {$_ }
                    } else {
                        Write-Host "No saved urls found. Press any key to exit!"
                        $key = [System.Console]::ReadKey($True)
                        exit
                    }
                }
                $url_list | Out-File "$dir_fullpath\tools\tmp\url.txt" -Encoding UTF8
                Write-Host "You are about to download the subscription files using the following urls:"
                $url_list
                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                $url_line = (Get-Content "$dir_fullpath\tools\tmp\url.txt" -Encoding UTF8 | Where-Object {$_ }) -split "`r?`n"
                for ($i = 0; $i -lt $url_line.Count; $i++) {
                    if ($url_line[$i] -match '^<.*> ') {
                        $url_line_tmp = ($url_line[$i]) -creplace '^<.*> (.*)$', '$1'
                        while ($True) {
                            if (($url_line_tmp -match '^[A-Z]:\\') -and (Test-Path -PathType Leaf -Path $url_line_tmp)) {
                                Copy-Item $url_line_tmp "$dir_fullpath\tools\tmp\aa$($i + 1).yaml"
                            } else {
                                try { Invoke-WebRequest -Uri $url_line_tmp -UserAgent "clash" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\tmp\aa$($i + 1).yaml" } catch {}
                            }
                            if (Test-Path -PathType Leaf -Path "$dir_fullpath\tools\tmp\aa$($i + 1).yaml") {
                                Write-Host "Successfully obtained the file for url $($i + 1): $url_line_tmp"
                                break
                            } else {
                                Write-Host "Failed to obtain file for url $($i + 1): $url_line_tmp"
                                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                                Write-Host "Please check the network or urls."
                                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                                Write-Host "Do you want to (A)skip this url (B)re-fetch the file? [A]|B"
                                CapsLock_on
                                while ($True) {
                                    if ([System.Console]::KeyAvailable) {
                                        $key = [System.Console]::ReadKey($True)
                                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") { 
                                            Write-Host "Your choice: "$key.Key
                                            break
                                        } elseif ($key.Key -eq "B") {
                                            Write-Host "Your choice: "$key.Key
                                            break
                                        } else {
                                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                        }
                                    }
                                }
                            }
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") { break }
                        }
                    } else {
                        $url_line_tmp = $url_line[$i]
                        while ($True) {
                            if (($url_line_tmp -match '^[A-Z]:\\') -and (Test-Path -PathType Leaf -Path $url_line_tmp)) {
                                Copy-Item $url_line_tmp "$dir_fullpath\tools\tmp\a$($i + 1).yaml"
                            } else {
                                try { Invoke-WebRequest -Uri $url_line_tmp -UserAgent "clash" -TimeoutSec $time_s1 -MaximumRedirection $max_redirection -OutFile "$dir_fullpath\tools\tmp\a$($i + 1).yaml" } catch {}
                            }
                            if (Test-Path -PathType Leaf -Path "$dir_fullpath\tools\tmp\a$($i + 1).yaml") {
                                Write-Host "Successfully obtained the file for url $($i + 1): $url_line_tmp"
                                break
                            } else {
                                Write-Host "Failed to obtain file for url $($i + 1): $url_line_tmp"
                                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                                Write-Host "Please check the network or urls."
                                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                                Write-Host "Do you want to (A)skip this url (B)re-fetch the file? [A]|B"
                                CapsLock_on
                                while ($True) {
                                    if ([System.Console]::KeyAvailable) {
                                        $key = [System.Console]::ReadKey($True)
                                        if ($key.Key -eq "Enter" -or $key.Key -eq "A") { 
                                            Write-Host "Your choice: "$key.Key
                                            break
                                        } elseif ($key.Key -eq "B") {
                                            Write-Host "Your choice: "$key.Key
                                            break
                                        } else {
                                            Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                                        }
                                    }
                                }
                            }
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") { break }
                        }
                    }
                } 
                break 
            }
        }
    }

    if (Test-Path "$dir_fullpath\tools\tmp\url.txt") { $url_line = (Get-Content "$dir_fullpath\tools\tmp\url.txt" -Encoding UTF8 | Where-Object {$_ }) -split "`r?`n" }
    $tmp_file = (Get-ChildItem -Path "$dir_fullpath\tools\tmp" -Filter "a*.yaml" -File | Select-Object -ExpandProperty Name) -split "`r?`n"
    $used_ports = Get-NetTCPConnection | Select-Object -ExpandProperty LocalPort
    $available_ports = 10000..20000 | Where-Object { $used_ports -notcontains $_ } | Get-Random -Count 1
    "[server]`nlisten = 127.0.0.1`nport = $available_ports" | Out-File "$dir_fullpath\tools\tmp\pref.toml" -Encoding UTF8
    Start-Process -FilePath $subconverter -WindowStyle Hidden
    for ($i = 0; $i -lt $tmp_file.Count; $i++) {
        $tmp_file_name = $tmp_file[$i]
        $j = $tmp_file_name -creplace '^a{1,2}(.*)\.yaml', '$1'
        Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=clash&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=$tmp_file_name" -OutFile "$dir_fullpath\tools\tmp\b$j.yaml"
        if ($tmp_file_name -match '^aa.*\.yaml') {
            $tmp_file_name_number = $tmp_file_name -creplace '^aa(.*)\.yaml$', '$1'
            $url_name_content = $url_line[$($tmp_file_name_number - 1)] -creplace '^<(.*)> .*$', '$1'
            $aa_content = Get-Content "$dir_fullpath\tools\tmp\b$j.yaml" -Encoding UTF8
            $aa_content -creplace "^(  - \{name: ['`"]*)([^'`"].*)$", "`$1<$url_name_content> `$2" | Out-File "$dir_fullpath\tools\tmp\b$j.yaml" -Encoding UTF8
        }
    }
    Get-Process -Name process_hidden_subconverter -ErrorAction SilentlyContinue | Stop-Process
    $b_files = (Get-ChildItem -Path "$dir_fullpath\tools\tmp\b*.yaml") -split "`r?`n"
    $b_output = @()
    $b_all_second_part = @()
    $b_output += "proxies:"
    foreach ($b_file in $b_files) {
        $b_matches = (Get-Content -Path $b_file -Encoding UTF8 | Select-String -Pattern '^  - \{name: ') -split "`r?`n"
        foreach ($b_match in $b_matches) {
            $b_parts = $b_match -split ', server: '
            $b_second_part = $b_parts[1].ToString().Trim()
            if ($b_all_second_part -notcontains $b_second_part) {
                $b_output += $b_match
                $b_all_second_part += $b_second_part
            }
        }
    }
    if ( $b_output | Where-Object {$_ -match '^  - \{name: '} ) {
        $b_output | Out-File "$dir_fullpath\tools\tmp\c.yaml" -Encoding UTF8
        Get-Content "$dir_fullpath\tools\tmp\c.yaml" -Encoding UTF8 | Where-Object {$_ } | Out-File "$dir_fullpath\tools\tmp\config.yaml" -Encoding UTF8
        while ($True)
        {
            $msg = @{}
            $msg = & $clash -d $dir_fullpath\tools\tmp -t
            $error1 = $msg | Select-String -Pattern 'proxy (\d+)' | ForEach-Object { $_.Matches.Groups[1].Value }
            $error2 = $msg | Select-String -Pattern 'yaml: line (\d+)' | ForEach-Object { $_.Matches.Groups[1].Value }
            $error3 = $msg | Select-String -Pattern "Can't find config"
            if ($error1 -or $error2) {
                if ($error1) { $line = [int]$error1 + 2 } else { $line = [int]$error2 + 1 }
                $test_yaml = Get-Content "$dir_fullpath\tools\tmp\config.yaml" -Encoding UTF8
                $test_yaml | Select-Object -Index ((0..($test_yaml.Count - 1)) -ne ($line - 1)) | Out-File "$dir_fullpath\tools\tmp\config.yaml" -Encoding UTF8
            } elseif ($error3) {
                if (Test-Path "$dir_fullpath\tools\tmp\config.yaml") { Remove-Item -Path "$dir_fullpath\tools\tmp\config.yaml" -Force }
                break
            } elseif ($msg -like "*test is successful*") {
                break
            } else {
                if (Test-Path "$dir_fullpath\tools\tmp\config.yaml") { Remove-Item -Path "$dir_fullpath\tools\tmp\config.yaml" -Force }
                break
            }
        }
    } 
    if ( (Test-Path "$dir_fullpath\tools\tmp\config.yaml") -and (Get-Content "$dir_fullpath\tools\tmp\config.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) ) {
        Copy-Item "$dir_fullpath\tools\tmp\config.yaml" "$dir_fullpath\config\yaml2\config1.yaml"
        if ((Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*<[^>]*> .*, server: "}).Count -ne 0) {
            Write-Host "Here are the statistics for valid nodes:"
            $url_name_list = ((Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*<[^>]*> .*, server: "}) -creplace "^  - \{name: ['`"]*(<[^>]*>) .*, server: .*$", '$1' | Select-Object -Unique) -split "`r?`n"
            for ($i = 0; $i -lt $url_name_list.Count; $i++) {
                $line = $url_name_list[$i]
                Write-Host "${line}: "(Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*$line .*, server: "}).Count
            }  
        }
        if ($mode -eq 0) {
            if ( $file_value -eq 7 ) {
                $local_file = Get-ChildItem -Path "$dir_fullpath\config\yaml1" -File | Select-Object -ExpandProperty Name
                if ($local_file) {
                    $local_file_content = Get-Content "$dir_fullpath\config\yaml1\*" -Encoding UTF8 | Where-Object {$_ }
                } else {
                    $local_file_content = ""
                }
                if ($local_file_content) {
                    Write-Host "Subscription file check is successful! All your valid subscription nodes have been consolidated into a temporary file $dir_fullpath\config\yaml2\config1.yaml."
                    Start-Sleep -Seconds 1
                    Write-Host "Do you want to save them to $dir_fullpath\config\yaml1\config.yaml and overwrite the original files in $dir_fullpath\config\yaml1? (Not saving doesn't interrupt your testing process for that file unless you re-select.) [Y]|N"
                } else {
                    Write-Host "Subscription file check is successful! All your valid subscription nodes have been consolidated into a temporary file $dir_fullpath\config\yaml2\config1.yaml."
                    Start-Sleep -Seconds 1
                    Write-Host "Do you want to save them to $dir_fullpath\config\yaml1\config.yaml? (Not saving doesn't interrupt your testing process for that file unless you re-select.) [Y]|N"
                }
                CapsLock_on
                while ($True) {
                    if ([System.Console]::KeyAvailable) {
                        $key = [System.Console]::ReadKey($True)
                        if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
                            Write-Host "Your choice: "$key.Key
                            Remove-Item -Path "$dir_fullpath\config\yaml1\*" -Force -Recurse
                            Copy-Item "$dir_fullpath\tools\tmp\config.yaml" "$dir_fullpath\config\yaml1\config.yaml"
                            Write-Host "The file has been saved as $dir_fullpath\config\yaml1\config.yaml."
                            Start-Sleep -Seconds 1
                            break
                        } elseif ($key.Key -eq "N") {
                            Write-Host "Your choice: "$key.Key
                            $file_value = 8
                            break
                        } else {
                            Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
                        }
                    }
                }
            } else {
                Remove-Item -Path "$dir_fullpath\config\yaml1\*" -Force -Recurse
                Copy-Item "$dir_fullpath\tools\tmp\config.yaml" "$dir_fullpath\config\yaml1\config.yaml"
                Write-Host "Local subscription file check is successful!"
                Start-Sleep -Seconds 1
                Write-Host "The updated file has been saved as $dir_fullpath\config\yaml1\config.yaml and overwrote the original files in $dir_fullpath\config\yaml1."
                Start-Sleep -Seconds 1
            }
            $file_value = 10
        }
    } else {
        if ($mode -eq 0) {
            Write-Host "There is no valid file. Press any key to exit!"
            $key = [System.Console]::ReadKey($True)
            exit
        }
        if ( $file_value -eq 7 ) {
            Write-Host "Subscription file check failed!"
        } else {
            Write-Host "Local subscription file check failed!"
        }
        Start-Sleep -Seconds 1
        $file_value = 11
    }
    if (Test-Path "$dir_fullpath\tools\tmp\config.yaml") { Remove-Item -Path "$dir_fullpath\tools\tmp\config.yaml" -Force }
    if ($mode -eq 1) { break }
    if ( $file_value -eq 10 ) {
        Write-Host "Do you want to (A)continue to test (B)re-select the files or the urls? [A]|B"
    } else {
        Write-Host "Do you want to (A)re-select the files or the urls or (B)exit? [A]|B"
    }
    CapsLock_on
    while ($True) {
        if ([System.Console]::KeyAvailable) {
            $key = [System.Console]::ReadKey($True)
            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                Write-Host "Your choice: "$key.Key
                if ( $file_value -eq 10 ) { $file_value = 12 }
                break
            } elseif ($key.Key -eq "B") {
                Write-Host "Your choice: "$key.Key
                if ( $file_value -eq 10 ) { 
                    break
                } else {
                    Start-Sleep -Seconds 1
                    exit
                }
            } else {
                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
            }
        }
    }
    if ( $file_value -eq 12 ) { break }
}

Write-Host "Part III: <$esc[32mTest Nodes$esc[0m>"
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
Write-Host "During the test, you can normally use proxy software such as Clash, V2RayN, but using VPN may affect the node test results; if you want to achieve the best ones, turning off the VPN may help with this."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
Write-Host "The results of the first test are often less accurate (fewer nodes passed), probably because the computer's CPU resources are underutilized."
if ($mode -eq 0) { Start-Sleep -Seconds 1 }
while ($True) {
Write-Host "If you have a lot of nodes and more than 50% of them are unavailable, then I suggest you simply filter the nodes first. Do you want to filter? Y|[N]"
if (Test-Path $dir_fullpath\config\yaml2\config2.yaml) { Remove-Item -Path $dir_fullpath\config\yaml2\config2.yaml -Force }
if (Test-Path $dir_fullpath\config\yaml2\config3.yaml) { Remove-Item -Path $dir_fullpath\config\yaml2\config3.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\d.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\d.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\e.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\e.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\f.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\f.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\h.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\h.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\i.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\i.yaml -Force }
if (Test-Path $dir_fullpath\tools\tmp\l.yaml) { Remove-Item -Path $dir_fullpath\tools\tmp\l.yaml -Force }
Remove-Item -Path "$dir_fullpath\config\yaml3\*" -Force -Recurse
Remove-Item -Path "$dir_fullpath\tools\tmp\g*.yaml" -Force -Recurse
$l_content = ((Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: .*?(, server: .*)$', '$1') -split "`r?`n"
$sum1 = $l_content.Count
for ($i = 0; $i -lt $l_content.Count; $i++) {
    $line = $l_content[$i]
    $new_line = "  - {name: NO$($i + 1)" + $line
    $l_content[$i] = $new_line
}
$l_content | Out-File "$dir_fullpath\tools\tmp\l.yaml" -Encoding UTF8
(Get-Content "$dir_fullpath\tools\tmp\l.yaml" -Encoding UTF8) -creplace '^  - \{name: (.*?), server: .*$', '      - $1' | Out-File "$dir_fullpath\tools\tmp\d.yaml" -Encoding UTF8
$l_content = Get-Content "$dir_fullpath\tools\tmp\l.yaml" -Raw -Encoding UTF8
$d_content = Get-Content "$dir_fullpath\tools\tmp\d.yaml" -Raw -Encoding UTF8
$prefix + $l_content + $suffix1 + $d_content + $suffix2 | Out-File "$dir_fullpath\config\yaml2\config2.yaml" -Encoding UTF8
CapsLock_on
while ($True) {
    if ([System.Console]::KeyAvailable) {
        $key = [System.Console]::ReadKey($True)
        if ($key.Key -eq "Y") {
            Write-Host "Your choice: "$key.Key
            while ($True) {
                Write-Host "Node filtering begins."
                Copy-Item "$dir_fullpath\config\yaml2\config2.yaml" "$dir_fullpath\tools\tmp\config.yaml"
                New-NetFirewallRule -DisplayName "Allow Inbound for process_hidden_clash" -Direction Inbound -Program "$clash" -Action Allow -Profile Any | Out-Null
                New-NetFirewallRule -DisplayName "Allow Outbound for process_hidden_clash" -Direction Outbound -Program "$clash" -Action Allow -Profile Any | Out-Null
                New-NetFirewallRule -DisplayName "Allow Inbound for process_hidden_curl" -Direction Inbound -Program "$curl" -Action Allow -Profile Any | Out-Null
                New-NetFirewallRule -DisplayName "Allow Outbound for process_hidden_curl" -Direction Outbound -Program "$curl" -Action Allow -Profile Any | Out-Null             
                Start-Process -FilePath "$clash" -ArgumentList "-d $dir_fullpath\tools\tmp" -WindowStyle Hidden
                $start = $sum1
                while ($True)
                {   
                    while ($True)
                    {
                        if ( (Get-Process -Name process_hidden_curl -ErrorAction SilentlyContinue).Count -gt $([Math]::Round($curl_sum/2)) ) { 
                            Start-Sleep -Seconds 5
                        } else {
                            break
                        }
                    }
                    $end = $start + 1 - $curl_sum
                    if ( $end -lt 1 ) { $end = 1 }
                    for ($i = $start; $i -ge $end; $i--) {
                        Start-Process -FilePath "$curl" -ArgumentList "-sH `"Authorization: Bearer $secret`" -o $dir_fullpath\tools\tmp\NO$i.log http://127.0.0.1:$ui_port/proxies/NO$i/delay?timeout=$time_ms&url=$url_test" -WindowStyle Hidden
                    }
                    if ( $end -eq 1 ) { break }
                    $start = $end - 1
                }
                Start-Sleep -Seconds $([Math]::Round(($time_ms*1.1)/1000))
                Get-Process -Name process_hidden_curl -ErrorAction SilentlyContinue | Stop-Process
                & $curl -sH "Authorization: Bearer $secret" -o $dir_fullpath\tools\tmp\proxies.log "http://127.0.0.1:$ui_port/proxies"
                (Get-Content $dir_fullpath\tools\tmp\proxies.log -Encoding UTF8) -creplace '"delay":0,', '' -creplace '("delay":[^,]*,)', "`n`$1" -creplace '"name":"([^"]*)"',  "`"name`":`$1`n" | Out-File $dir_fullpath\tools\tmp\proxies_tmp.log -Encoding UTF8
                Get-Content $dir_fullpath\tools\tmp\proxies_tmp.log -Encoding UTF8 | ForEach-Object {
                    if ($_ -match '^"delay":[^,]*,"meanDelay":[^}]*}],"name":.*$') {
                        $log_name = $_ -creplace '^"delay":[^,]*,"meanDelay":[^}]*}],"name":(.*)$', '$1'
                        $_ -creplace '^"delay":([^,]*),"meanDelay":([^}]*)}],"name":.*$', '{"delay":$1,"meanDelay":$2}'  | Out-File "$dir_fullpath\tools\tmp\$log_name.log" -Encoding UTF8
                    }
                }
                Get-Process -Name process_hidden_curl -ErrorAction SilentlyContinue | Stop-Process
                Get-Process -Name process_hidden_clash -ErrorAction SilentlyContinue | Stop-Process
                Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Allow Inbound for process_hidden_*" -or $_.DisplayName -like "Allow Outbound for process_hidden_*" } | Remove-NetFirewallRule
                if (Test-Path "$dir_fullpath\tools\tmp\config.yaml") { Remove-Item -Path "$dir_fullpath\tools\tmp\config.yaml" -Force }

                $log_match_lines = @()
                $log_files = (Get-ChildItem -Path "$dir_fullpath\tools\tmp" -Filter "NO*.log") -split "`r?`n"
                foreach ($log_file in $log_files) {
                    $log_file_content = Get-Content $dir_fullpath\tools\tmp\$log_file -First 1 -Encoding UTF8
                    if ($log_file_content -match '{"delay":\d+,') {
                        $log_file_number = $log_file -creplace '^NO(\d+)\.log$', '$1'
                        $log_match_line = Select-String -Path "$dir_fullpath\config\yaml2\config2.yaml" -Pattern "^  - {name: NO$log_file_number,"
                        $log_match_lines += $log_match_line.Line
                    }
                }
                $log_match_lines = $log_match_lines -split "`r?`n"
                for ($i = 0; $i -lt $log_match_lines.Count; $i++) {
                    $line = ($log_match_lines[$i]) -creplace '^  - {name: .*?(, server: .*)$', '$1'
                    $new_line = "  - {name: NO$($i + 1)" + $line
                    $log_match_lines[$i] = $new_line
                }
                $log_match_lines | Out-File "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8
                if ( -not(Test-Path "$dir_fullpath\tools\tmp\e.yaml") -or -not(Get-Content "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) ) {
                    Write-Host "There are no nodes available to access the target site! Please check the network or files."
                    if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                    Write-Host "Do you want to (A)re-filter the nodes or (B)exit? [A]|B"
                    CapsLock_on
                    while ($True) {
                        if ([System.Console]::KeyAvailable) {
                            $key = [System.Console]::ReadKey($True)
                            if ($key.Key -eq "Enter" -or $key.Key -eq "A") {
                                Write-Host "Your choice: "$key.Key
                                break
                            } elseif ($key.Key -eq "B") {
                                Write-Host "Your choice: "$key.Key
                                if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                                exit
                            } else {
                                Write-Host "Invalid choice! Please select either 'A[Enter]' or 'B'."
                            }
                        }
                    }
                    continue
                } else {
                    Write-Host "Filtering completed."
                    if ($mode -eq 0) { Start-Sleep -Seconds 1 }
                    break
                }
            }
            break
        } elseif ($key.Key -eq "Enter" -or $key.Key -eq "N") {
            Write-Host "Your choice: "$key.Key
            Get-Content "$dir_fullpath\config\yaml2\config2.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '} | Out-File "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8
            break
        } else {
            Write-Host "Invalid choice! Please select either 'Y' or 'N[Enter]'."
        }
    }
}

Write-Host "Node test begins."
$sum2 = (Get-Content "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8).Count
Write-Host "Estimated maximum time: $([Math]::Ceiling($([Math]::Min($sum2, $clash_sum))*0.25 + $([Math]::Ceiling($sum2/$clash_sum))*$time_s3 + 2)) seconds."
(Get-Content "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8) -creplace '^  - \{name: (.*?), server: .*$', '      - $1' | Out-File "$dir_fullpath\tools\tmp\f.yaml" -Encoding UTF8
$e_content = Get-Content "$dir_fullpath\tools\tmp\e.yaml" -Raw -Encoding UTF8
$f_content = Get-Content "$dir_fullpath\tools\tmp\f.yaml" -Raw -Encoding UTF8
$prefix + $e_content + $suffix3 + $f_content + $suffix4 | Out-File "$dir_fullpath\config\yaml2\config3.yaml" -Encoding UTF8

$e_content = Get-Content "$dir_fullpath\tools\tmp\e.yaml" -Encoding UTF8
$f_content = Get-Content "$dir_fullpath\tools\tmp\f.yaml" -Encoding UTF8
$used_ports = Get-NetTCPConnection | Select-Object -ExpandProperty LocalPort
$available_ports = 3000..10000 | Where-Object { $used_ports -notcontains $_ } | Get-Random -Count $($clash_sum*2)
for ($j = 1; $j -le $clash_sum; $j++) {
if (-not(Test-Path -PathType Container -Path "$dir_fullpath\tools\tmp\$j")) {
    if ($j -gt $sum2) { break }
    if (Test-Path "$dir_fullpath\tools\tmp\$j") { Remove-Item -Path "$dir_fullpath\tools\tmp\$j" -Force }
    New-Item -ItemType Directory -Path "$dir_fullpath\tools\tmp\$j" | Out-Null
}
if (-not(Test-Path $dir_fullpath\tools\tmp\$j\process_hidden_clash.exe)) { Copy-Item $dir_fullpath\tools\file\clash-$arch1.exe $dir_fullpath\tools\tmp\$j\process_hidden_clash.exe }
if (-not(Test-Path $dir_fullpath\tools\tmp\$j\Country.mmdb)) { Copy-Item $dir_fullpath\tools\file\Country.mmdb $dir_fullpath\tools\tmp\$j\Country.mmdb }
New-NetFirewallRule -DisplayName "Allow Inbound for process_hidden_clash_$j" -Direction Inbound -Program "$dir_fullpath\tools\tmp\$j\process_hidden_clash.exe" -Action Allow -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "Allow Outbound for process_hidden_clash_$j" -Direction Outbound -Program "$dir_fullpath\tools\tmp\$j\process_hidden_clash.exe" -Action Allow -Profile Any | Out-Null
$ui_port = $available_ports[$($j*2 - 1)]
$proxy_port = $available_ports[$($j*2)]
$prefix = @"
mixed-port: $proxy_port
allow-lan: false
mode: Rule
log-level: info
ipv6: true
authentication: ["${user}:$pass"]
external-controller: :$ui_port
secret: $secret
proxies:

"@
$e_content_part = @()
$f_content_part = @()
$i = $j
while ($True){
    if ($i -gt $sum2) { break }
    $e_content_part = $e_content_part + $e_content[$($i - 1)]
    $f_content_part = $f_content_part + $f_content[$($i - 1)]
    $i = $i + $clash_sum
}
$prefix + ($e_content_part | Out-String) + $suffix3 + ($f_content_part | Out-String) + $suffix4 | Out-File "$dir_fullpath\tools\tmp\$j\config.yaml" -Encoding UTF8
$test_file = @"
`$dir_fullpath = "$dir_fullpath"
`$clash = "`$dir_fullpath\tools\tmp\$j\process_hidden_clash.exe"
`$curl = "$curl"
`$secret = "$secret"
`$url1 = "http://127.0.0.1:$ui_port/connections"
`$url2 = "http://127.0.0.1:$ui_port/proxies/SELECT"
`$url_test = "$url_test"
`$user = "$user"
`$pass = "$pass"
`$sum2 = $sum2

Start-Process -FilePath `$clash -ArgumentList "-d `$dir_fullpath\tools\tmp\$j" -WindowStyle Hidden
`$select_content = @()
`$i = $j
while (`$True)
{
    if ( `$i -gt `$sum2 ) { break }
    `$headers = @{
        "Authorization" = "Bearer `$secret"
    }
    `$body = @{
        "name" = "NO`$i"
    } | ConvertTo-Json
    Invoke-RestMethod -Uri `$url1 -Method Delete -Headers `$headers
    Invoke-RestMethod -Uri `$url2 -Method Put -Headers `$headers -Body `$body
    `$result = ""
    `$result1 = ""
    `$result = & `$curl -x 127.0.0.1:$proxy_port --proxy-user `${user}:`$pass -sL --max-time $time_s3 `$url_test
    `$result1 = `$result | Where-Object {`$_ -match '^.*Sorry, you have been blocked|^.*Unable to load site'}
    if (`$result -and -not(`$result1)) {
        `$log_match_line = Select-String -Path "`$dir_fullpath\config\yaml2\config3.yaml" -Pattern "^  - {name: NO`$i,"
        `$select_content += `$log_match_line.Line
        Write-Host "`$i/`${sum2}: Yes"
    } else {
        Write-Host "`$i/`${sum2}: No"
    }
    `$i = `$i + $clash_sum
}
`$select_content | Out-File "`$dir_fullpath\tools\tmp\g$j.yaml" -Encoding UTF8
Get-Process -Name process_hidden_clash -ErrorAction SilentlyContinue | Where-Object { `$_.Path -eq `$clash } | Stop-Process
"@
$test_file | Out-File "$dir_fullpath\tools\tmp\$j\test.ps1" -Encoding UTF8
Start-Process powershell -ArgumentList "-File $dir_fullpath\tools\tmp\$j\test.ps1" -WindowStyle Hidden
}
while ($True)
{   
    if ((Get-ChildItem -Path "$dir_fullpath\tools\tmp" -Filter "g*.yaml").Count -ge $clash_sum -and (Get-Process -Name process_hidden_clash -ErrorAction SilentlyContinue).Count -eq 0) {
        Get-Process -Name process_hidden_curl -ErrorAction SilentlyContinue | Stop-Process
        Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Allow Inbound for process_hidden_*" -or $_.DisplayName -like "Allow Outbound for process_hidden_*" } | Remove-NetFirewallRule
        break
    } else {
        Start-Sleep -Seconds 2
    }
}

$match_lines = @()
$match_lines += "proxies:"
$g_content = (Get-Content "$dir_fullpath\tools\tmp\g*.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: .*?(, server: .*)$', '$1'
$config_content = (Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -split "`r?`n"
foreach ($line in $config_content) {
    $match_line = $g_content | Where-Object { $line -match [regex]::Escape($_) }
    if ($match_line) {
        $match_lines += $line
    }
}
if ($match_lines | Where-Object {$_ -match '^  - \{name: '}) {
    $match_lines | Out-File "$dir_fullpath\config\yaml3\config1.yaml" -Encoding UTF8
    Write-Host "Names of the nodes that passed the test are as follows:"
    $originalEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    ($match_lines | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: (.*?), server: .*$', '$1'
    [Console]::OutputEncoding = $originalEncoding
    if ($mode -eq 0) { Start-Sleep -Seconds 1 }
    if ((Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*<[^>]*> .*, server: "}).Count -ne 0) {
        Write-Host "Here are the statistics for the nodes that passed the test:"
        $url_name_list = ((Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*<[^>]*> .*, server: "}) -creplace "^  - \{name: ['`"]*(<[^>]*>) .*, server: .*$", '$1' | Select-Object -Unique) -split "`r?`n"
        for ($i = 0; $i -lt $url_name_list.Count; $i++) {
            $line = $url_name_list[$i]
            Write-Host $line": "(Get-Content "$dir_fullpath\config\yaml3\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*$line .*, server: "}).Count"/"(Get-Content "$dir_fullpath\config\yaml2\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match "^  - \{name: ['`"]*$line .*, server: "}).Count
        }  
    }

    (Get-Content "$dir_fullpath\config\yaml3\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: (.*?), server: .*$', '      - $1' | Out-File "$dir_fullpath\tools\tmp\h.yaml" -Encoding UTF8
    $h_content = Get-Content "$dir_fullpath\tools\tmp\h.yaml" -Raw -Encoding UTF8
    $match_lines + $suffix3 + $h_content + $suffix4 | Out-File "$dir_fullpath\config\yaml3\config6.yaml" -Encoding UTF8
    $simple_content = Get-Content "$dir_fullpath\config\yaml3\config6.yaml" -Encoding UTF8 | Where-Object {$_}
    $simple_content | Out-File "$dir_fullpath\config\yaml3\config6.yaml" -Encoding UTF8
    Copy-Item "$dir_fullpath\config\yaml2\config1.yaml" "$dir_fullpath\tools\tmp\i.yaml"
    $j_content = (Get-Content "$dir_fullpath\config\yaml3\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: (.*?), server: .*$', '$1' -creplace '[\[\]\(\)\{\}\^\$\.\*\+\?\|]', '\$&' -creplace '`', '\x60' -creplace '^"?', '`(^"?' -creplace '"$', '' -creplace '$', '"?$)' -join '' -creplace '$', '`http://www.apple.com/library/test/success.html`300,,50'
    $k_content = (Get-Content "$dir_fullpath\config\yaml3\config1.yaml" -Encoding UTF8 | Where-Object {$_ -match '^  - \{name: '}) -creplace '^  - \{name: (.*?), server: .*$', '$1' -creplace '[\[\]\(\)\{\}\^\$\.\*\+\?\|]', '\$&' -creplace '`', '\x60' -creplace '^"?', '`(^"?' -creplace '"$', '' -creplace '$', '"?$)' -join ''
    $ini_content = (Get-Content "$dir_fullpath\tools\tmp\OpenAI.ini" -Encoding UTF8) -split "`r?`n"
    $ini_content_mod = @()
    for ($i = 0; $i -lt $ini_content.Count; $i++) {
        $line = $ini_content[$i]
        if ($line -match '^.*OpenAI Unlocked Nodes - Auto Select`url-test') {
            $ini_content_mod += ($line -creplace '^(.*OpenAI Unlocked Nodes - Auto Select`url-test).*$', '$1') + $j_content
        } elseif ($line -match '.*OpenAI Unlocked Nodes - Manual Select`select') {
            $ini_content_mod += ($line -creplace '^(.*OpenAI Unlocked Nodes - Manual Select`select).*$', '$1') + $k_content
        } else {
            $ini_content_mod += $line
        }
    }
    $ini_content_mod | Out-File "$dir_fullpath\tools\tmp\OpenAI.ini" -Encoding UTF8
    $used_ports = Get-NetTCPConnection | Select-Object -ExpandProperty LocalPort
    $available_ports = 10000..20000 | Where-Object { $used_ports -notcontains $_ } | Get-Random -Count 1
    $base | Out-File "$dir_fullpath\tools\tmp\all_base.tpl" -Encoding UTF8
    "version = 1`n[common]`nsurfboard_rule_base = 'all_base.tpl'`nquan_rule_base = 'all_base.tpl'`n[node_pref]`n[managed_config]`n[surge_external_proxy]`n[emojis]`n[ruleset]`n[template]`n[server]`nlisten = '127.0.0.1'`nport = $available_ports`n[advanced]`nmax_pending_connections = 0`nmax_concurrent_threads = 4`nmax_allowed_rulesets = 0`nmax_allowed_rules = 0`nmax_allowed_download_size = 0" | Out-File "$dir_fullpath\tools\tmp\pref.toml" -Encoding UTF8
    Start-Process -FilePath $subconverter -WindowStyle Hidden
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=v2ray&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml" -OutFile "$dir_fullpath\config\yaml3\config2.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=trojan&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml" -OutFile "$dir_fullpath\config\yaml3\config3.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=ss&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml" -OutFile "$dir_fullpath\config\yaml3\config4.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=ssr&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml" -OutFile "$dir_fullpath\config\yaml3\config5.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=clash&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml&config=OpenAI.ini" -OutFile "$dir_fullpath\config\yaml3\config7.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=quan&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml&config=OpenAI.ini" -OutFile "$dir_fullpath\config\yaml3\config8.yaml"
    Invoke-WebRequest -Uri "http://127.0.0.1:$available_ports/sub?target=surfboard&insert=true&new_name=true&scv=true&udp=true&exclude=&include=&url=i.yaml&config=OpenAI.ini" -OutFile "$dir_fullpath\config\yaml3\config9.yaml"
    Get-Process -Name process_hidden_subconverter -ErrorAction SilentlyContinue | Stop-Process
    Write-Host "The following is information about the output file:"
    Write-Host "$dir_fullpath\config\yaml3\config1.yaml records information about the above nodes."
    Write-Host "$dir_fullpath\config\yaml3\config2.yaml is the V2Ray file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config3.yaml is the Trojan file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config4.yaml is the Shadowsocks file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config5.yaml is the ShadowsocksR file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config6.yaml is the Clash file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config7.yaml is the Clash triage file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config8.yaml is the Quantumult triage file for the above node."
    Write-Host "$dir_fullpath\config\yaml3\config9.yaml is the Surfboard triage file for the above node."
} else {
    Write-Host "No node passed the test! Please check the network or files."
    if ($mode -eq 0) { Start-Sleep -Seconds 1 }
}
Write-Host "Do you want to re-test? [Y]|N"
CapsLock_on
while ($True) {
    if ([System.Console]::KeyAvailable) {
        $key = [System.Console]::ReadKey($True)
        if ($key.Key -eq "Enter" -or $key.Key -eq "Y") {
            Write-Host "Your choice: "$key.Key
            break
        } elseif ($key.Key -eq "N") {
            Write-Host "Your choice: "$key.Key
            break
        } else {
            Write-Host "Invalid choice! Please select either 'Y[Enter]' or 'N'."
        }
    }
}
if ($key.Key -eq "N") { break }
}

Write-Host "Press 'E' to exit"
CapsLock_on
while ($True) {
    if ([System.Console]::KeyAvailable) {
        $key = [System.Console]::ReadKey($True)
        if ($key.Key -eq "E") {
            Write-Host "Your input: "$key.Key
            Start-Sleep -Seconds 1
            exit
        } else {
            Write-Host "Invalid input! Please press 'E'."
        }
    }
}
