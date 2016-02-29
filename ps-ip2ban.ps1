$regex = [regex] "Source Network Address:\t(\d+\.\d+\.\d+\.\d+)"; 
$date = (Get-Date).AddDays(-1).ToString('ddMMyyyy')
$date1 = (Get-Date).AddDays(-2).ToString('ddMMyyyy')
# $date = (Get-Date).AddHours(-$x).ToString('hhmmss')

# remove firewall rules from the period before (if exist)
if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Microsoft Windows Server 2008 R2 Datacenter") {
    foreach ($ips in ((netsh advfirewall firewall show rule name=all| find "Rule Name:" | Select-String -Pattern (Get-Date).AddDays(-1).ToString('ddMMyyyy')) -replace "Rule Name:","") -replace " ","") {
        netsh advfirewall firewall delete rule name=$ips
    }
}
else {
    Get-NetFirewallRule -DisplayName $date1"*" | Remove-NetFirewallRule
}

#remove firewall rules from the period before (if exist)
if (Get-Service -Name *SQL* | where {$_.Status -match "Running"}) {
    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Microsoft Windows Server 2008 R2 Datacenter") {
        foreach ($ips in ((netsh advfirewall firewall show rule name=all| find "Rule Name:" | Select-String -Pattern (Get-Date).AddDays(-1).ToString('ddMMyyyy')) -replace "Rule Name:","") -replace " ","") {
        netsh advfirewall firewall delete rule name=$ips
    }}
    else {
        Get-NetFirewallRule -DisplayName $date1"*" | Remove-NetFirewallRule
    }
}


# Add IP Addresses from the Windows EventLog
if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Microsoft Windows Server 2008 R2 Datacenter") {
    foreach ($ipad in (Get-EventLog Security -InstanceId 4625 -After (Get-Date).AddDays(-1) | foreach {$m = $regex.Match($_.Message); $ip = $m.groups[1].Value; $ip;} | where {$_ -ne ""} | select -Unique))
    {
        netsh advfirewall firewall add rule name=$date"_blockip_"$ipad protocol=any dir=in action=block remoteip=$ipad
        }
    }
else {
    foreach ($ipad in (Get-EventLog Security -InstanceId 4625 -After (Get-Date).AddDays(-1) | foreach {$m = $regex.Match($_.Message); $ip = $m.groups[1].Value; $ip;} | where {$_ -ne ""} | select -Unique))
    {
        New-NetFirewallRule -DisplayName $date"_blockip_"$ipad -Profile Public -Direction Inbound -Protocol Any -Action Block -Enabled True -RemoteAddress $ipad
    }
}

# Add IP Addresses from the Application Log - For MS SQL Server
if (Get-Service -Name *SQL* | where {$_.Status -match "Running"}) {
    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Microsoft Windows Server 2008 R2 Datacenter") {
        foreach ($apip in (((Get-EventLog -LogName Application -InstanceId 3221243928 -Newest 200 | select -ExpandProperty Message).Split("["+"]"+":") -match "\d+\.\d+\.\d+\.\d+") -replace " ","" | select -Unique))
        {
            netsh advfirewall firewall add rule name=$date"_SQL_blockip_"$apip protocol=any dir=in action=block remoteip=$apip
        }
    }
    else {
        New-NetFirewallRule -DisplayName $date"_SQL_blockip_"$apip -Profile Public -Direction Inbound -Protocol Any -Action Block -Enabled True -RemoteAddress $apip
        }
}
else{
}
