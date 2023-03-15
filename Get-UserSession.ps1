<#
Agentless, pure "living off the land" (No dependencies required, e.g. no ActiveDirectory Module needed or RSAT) for mapping user session in a 'Hacktive Directory' domain.
Run w/account that has Local Admin on domain endpoints. relays on port 445 to be open on the endPoints (quser.exe tool is used).

By default, tries to query all enabled computer accounts in the domain. Can also specify specific computer(s).

Comments welcome to 1nTh35h311 (yossis@protonmail.com)
Version: 1.0.2
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

$HostsToQuery | Foreach {
    $Computer = $_
     Write-Host "Querying $Computer ($i out of $TotalCount)"

     # Port-Ping the host first, to improve performance/shorten timeout
     # NOTE: if no Firewall blocking SMB 445 on Endpoints, step can be skipped. simply remark it in the code if needed
     if (($Computer | Invoke-PortPing) -eq "True") {
            $QueryData = .\quser.exe /Server:$Computer;
            if ($QueryData -notlike "No User exists for ") {
                $Obj = ($QueryData).SubString(1) -replace '\s{2,}', ',' | ConvertFrom-CSV;
                $obj | foreach {Write-Host "$Computer logged in by $($_.USERNAME.ToUpper()) (State: $($_.STATE))" -ForegroundColor Cyan}
		$Obj | ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name ComputerName -Value $computer -Force}
                $global:SessionList += $Obj;
                $Obj | Export-Csv $ReportFile -NoTypeInformation -Append;
                Clear-Variable obj, QueryData; $i++
            }
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
    $global:SessionList | where username -eq $username
    }
    until ($username -eq '')
}

Write-Host Type '$global:SessionList' to see the full session list in memory. -ForegroundColor Magenta;
# NOTE: you can use this global variable to query sessions further and/or export them to other formats, e.g. 
# To a grid: $global:SessionList | Out-GridView
# or JSON: $global:SessionList | ConvertTo-Json | Out-File .\Sessions.json