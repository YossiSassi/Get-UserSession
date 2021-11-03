<#
No dependencies required (e.g. no ActiveDirectory Module needed or RSAT)
Run w/account that has Local Admin on domain endpoints. relays on port 445 to be open on the endPoints.

Comments welcome to yossis@protonmail.com
#>

$DomainName = ([adsi]'').name
$ReportFile = "$(Get-Location)\Sessions_$($DomainName)_$(Get-Date -Format ddMMyyyyHHmmss).csv"
$CurrentDirectory = Get-Location

#$Computers = Get-ADComputer -Filter {Enabled -eq 'true'}
# Get all Enabled computer accounts 
$Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$Searcher.Filter = "(&(objectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
$Searcher.PageSize = 50000 # by default, 1000 are returned for adsiSearcher. this script will handle up to 50K acccounts.
$Computers = ($Searcher.Findall())
$TotalCount = $Computers.Count

# function to ensure port 445 is open on destination (quser, qwinsta etc relay on it - queries done over SMB)
filter Invoke-PortPing {((New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,445)).Wait(100)}
#filter Invoke-Ping {(New-Object System.Net.NetworkInformation.Ping).Send($_,100)}

# Set current location to the quser.exe tool
Set-Location $env:windir\system32;

$global:SessionList = @();
[int]$i = 1;

# Get the current Error Action Preference
$CurrentEAP = $ErrorActionPreference
# Set script not to alert for errors
$ErrorActionPreference = "silentlycontinue"

$Computers.Properties.dnshostname | Foreach {
    $Computer = $_
     Write-Host "Querying $Computer ($i out of $TotalCount)"

     # Port-Ping the host first, to improve performance/shorten timeout
     # NOTE: if no Firewall blocking SMB 445 on Endpoints, step can be skipped. simply remark it in the code if needed
     if (($Computer | Invoke-PortPing) -eq "True") {
        $TempData = .\quser.exe /Server:$Computer | ForEach { (($_.trim() -replace "\s+",","))}
        #$queryResults = (($TempData -split '\n')[0] + '-2' | Out-String).trim() + "`n" + ($TempData | Select -Skip 1 | Out-String).trim() | ConvertFrom-Csv
        $TempData | select -Skip 1 | foreach {
            $TempSession = $_;
            $Obj = New-Object psobject
            $Obj | Add-Member -MemberType NoteProperty -Name UserName -Value $TempSession.Split(",")[0] -Force
            
            switch ($(($TempSession).split(",").count -eq 7))
            {
                $True {
                    # Probably returned No Sessionname
                    $Obj | Add-Member -MemberType NoteProperty -Name ID -Value $TempSession.Split(",")[1] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name State -Value $TempSession.Split(",")[2] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name IdleTime -Value $TempSession.Split(",")[3] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name LogonDate -Value $TempSession.Split(",")[4] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name LogonTime -Value "$($TempSession.Split(",")[5]) $($TempSession.Split(",")[6])" -Force
                    $User = $Obj.USERNAME.ToUpper()
                    If (($User -match "[a-z]") -and ($User -ne $NULL)) {
                    Write-Host $Computer logged in by $User on session type $($queryResult.STATE) -ForegroundColor Cyan
                    $Obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer -Force
                    $global:SessionList += $Obj
                    $obj = $NULL
                    }
                } 
                $false {
                    $Obj | Add-Member -MemberType NoteProperty -Name SessionName -Value $TempSession.Split(",")[1] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ID -Value $TempSession.Split(",")[2] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name State -Value $TempSession.Split(",")[3] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name IdleTime -Value $TempSession.Split(",")[4] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name LogonDate -Value $TempSession.Split(",")[5] -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name LogonTime -Value "$($TempSession.Split(",")[6]) $($TempSession.Split(",")[7])" -Force
                    $User = $Obj.USERNAME.ToUpper()
                    If (($User -match "[a-z]") -and ($User -ne $NULL)) {
                    Write-Host $Computer logged in by $User on session type $($queryResult.STATE) -ForegroundColor Cyan
                    $Obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer -Force
                    $global:SessionList += $Obj
                    $Obj | Export-Csv $ReportFile -NoTypeInformation -Append
                    $obj = $NULL
                }                
            }                       
        }
        
            }
        }
     $i++
    }
   
# Set back error preference, as well as current directory from which the script was ran
$ErrorActionPreference = $CurrentEAP
Set-Location $CurrentDirectory

Write-Host `nTotal of $global:SessionList.Count sessions found -ForegroundColor Green;
Write-Host Report file saved to $ReportFile`n -ForegroundColor Cyan;

# allow in memory query of the collected sessions info
Do {
    Write-Host "Type the username you wish to see the Session(s) for, or press ENTER to exit:" -ForegroundColor Yellow
    $username = Read-Host
    $global:SessionList | where username -eq $username
    }
    until ($username -eq '')

Write-Host Type '$global:SessionList' to see the full session list in memory. -ForegroundColor Cyan;
# NOTE: you can use this global variable to query sessions further and/or export them to other formats, e.g. 
# To a grid: $global:SessionList | Out-GridView
# or JSON: $global:SessionList | ConvertTo-Json | Out-File .\Sessions.json