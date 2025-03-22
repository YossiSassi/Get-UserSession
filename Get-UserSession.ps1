<#
Agentless, pure "living off the land" (No dependencies required, e.g. no ActiveDirectory Module needed or RSAT) for mapping user session in a 'Hacktive Directory' domain.
Run w/account that has Local Admin on domain endpoints. relays on port 445 to be open on the endPoints (quser.exe tool is used).

By default, tries to query all enabled computer accounts in the domain. Can also specify specific computer(s).

Comments welcome to 1nTh35h311 (yossis@protonmail.com)
Version: 1.0.3
v1.0.3 - An issue fixed by Elrwes/Erland Westervik (Thank you!) resulting in unaligned property values, because SESSIONNAME is empty for disconnected sessions, and the delimiter was spaces.
v1.0.2 - bug fix not displaying some fields correctly (March 23')
#>
param (
    [cmdletbinding()]
    [parameter(mandatory=$false)]
    [string[]]$ComputerName
)

$DomainName = ([adsi]'').name;
$ReportFile = "$(Get-Location)\Sessions_$($DomainName)_$(Get-Date -Format ddMMyyyyHHmmss).csv";
$CurrentDirectory = Get-Location;

if (!$ComputerName)
    {
        Write-Host "Querying all enabled & accessible computer accounts in domain $DomainName... (Default)" -ForegroundColor Green;
        # Get all Enabled computer accounts 
        #$Computers = Get-ADComputer -Filter {Enabled -eq 'true'}
        $Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"");
        $Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))";
        $Searcher.PageSize = 100000; # by default, 1000 are returned for adsiSearcher. this script will handle up to 100K acccounts.
        $Computers = ($Searcher.Findall());
        $HostsToQuery = $Computers.Properties.dnshostname;
        $TotalCount = $HostsToQuery.Count;
    }
else # specific computer(s) specified
    {
        Write-Host "Querying computers specified. " -NoNewline -ForegroundColor Yellow; Write-Host " Run without any parameters to query ALL computers in domain $DomainName." -ForegroundColor Green;
        $HostsToQuery = $ComputerName;
        $TotalCount = ($ComputerName | Measure-Object).Count
    }

# function to ensure port 445 is open on destination (quser, qwinsta etc relay on it - queries done over SMB)
filter Invoke-PortPing {((New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,445)).Wait(100)}
#filter Invoke-Ping {(New-Object System.Net.NetworkInformation.Ping).Send($_,100)}

# Set current location to the quser.exe tool
Set-Location $env:windir\system32;

$global:SessionList = @();
[int]$i = 1;

# Get the current Error Action Preference
$CurrentEAP = $ErrorActionPreference;
# Set script not to alert for errors
$ErrorActionPreference = "silentlycontinue";

$HostsToQuery | ForEach-Object {
    $Computer = $_
     Write-Host "Querying $Computer ($i out of $TotalCount)"

     # Port-Ping the host first, to improve performance/shorten timeout
     # NOTE: if no Firewall blocking SMB 445 on Endpoints, step can be skipped. simply remark it in the code if needed
     if (($Computer | Invoke-PortPing) -eq "True") {
            $QueryData = .\quser.exe /Server:$Computer;
            if ($QueryData -notlike "No User exists for ") {
                
                # SESSIONNAME is empty for disconnected sessions.
                # This will cause property values to shift one place to the left, when using spaces as delimiter.
                # As a fix, we can count the fields/values to handle active/disconnected case different.
                $Objects = @()
                $Lines = $QueryData.Trim().Split("`n") | Select-Object -Skip 1
                foreach ($Line in $Lines) {             
                    $Fields = $Line -split '\s{2,}'
                    if ($Fields.count -eq 6) {
                        $Obj = [PSCustomObject]@{
                            COMPUTERNAME = $Computer
                            USERNAME     = $Fields[0]
                            SESSIONNAME  = $Fields[1]
                            ID           = $Fields[2]
                            STATE        = $Fields[3]
                            IDLE_TIME    = $Fields[4]
                            LOGON_TIME   = $Fields[5]
                        }
                    }
                    elseif ($fields.count -eq 5) {
                        $Obj = [PSCustomObject]@{
                            COMPUTERNAME = $Computer
                            USERNAME     = $Fields[0]
                            SESSIONNAME  = ''
                            ID           = $Fields[1]
                            STATE        = $Fields[2]
                            IDLE_TIME    = $Fields[3]
                            LOGON_TIME   = $Fields[4]
                        }
                    }
                    $Objects += $Obj
                    Clear-Variable Fields, Obj
                }

                # Add the object to the array
                $global:SessionList += $Objects

                $Objects | ForEach-Object { Write-Host "$Computer logged in by $($_.USERNAME.ToUpper()) (State: $($_.STATE))" -ForegroundColor Cyan } 
                $Objects | Export-Csv $ReportFile -NoTypeInformation -Append
                Clear-Variable Lines, Objects
                $i++
            }
            Clear-Variable QueryData
    }
}

# Set back error preference, as well as current directory from which the script was ran
$ErrorActionPreference = $CurrentEAP;
Set-Location $CurrentDirectory;

Write-Host `nTotal of $global:SessionList.Count sessions found -ForegroundColor Green;
Write-Host Report file saved to $ReportFile`n -ForegroundColor Gray;

if ($global:SessionList.Count -ge 2) {
# allow in memory query of the collected sessions info
Do {
    Write-Host "Type the username you wish to see the Session(s) for, or press ENTER to exit:" -ForegroundColor Yellow
    $username = Read-Host
    $global:SessionList | Where-Object username -eq $username
    }
    until ($username -eq '')
}

Write-Host Type '$global:SessionList' to see the full session list in memory. -ForegroundColor Magenta;
# NOTE: you can use this global variable to query sessions further and/or export them to other formats, e.g.
# To a grid: $global:SessionList | Out-GridView
# or JSON: $global:SessionList | ConvertTo-Json | Out-File .\Sessions.json