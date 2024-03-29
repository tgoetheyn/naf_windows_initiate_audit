# Script name:   	naf_initiate_ms_server_audit.ps1
# Version:			v1.08.151007
# Created on:    	15/09/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Initiates audit of a Windows host and output to Html or Logstash
# On Github:		https://github.com/willemdh/naf_windows_initiate_audit
# On OutsideIT:		http://outsideit.net/naf-windows-initiate-audit
# Recent History:       	
#	11/06/15 => Fixed admin, disk and service html
#	13/06/15 => finalized services, admins
#	15/06/15 => Finalized software and network adapters
#	16/06/15 => Updated fieldnames and cleanup auditstruct
#	07/10/15 => Improved write-log and cleanup following ISESteroids recommendations, updated NAF report path
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 2.0

$AuditStruct = New-Object PSObject -Property @{
    audit_start = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'); 
	audit_end = '';
    audit_duration = '';
    audit_executer = ("$ENV:USERDOMAIN\$ENV:USERNAME")
	audit_exitcode = 3;
    hostname = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower();	
    win_test_ping = 'Unknown';
    win_test_wmi = 'Unknown';
    win_test_eventlog = 'Unknown';
    host_version ='';
    host_caption = '';
    host_service_pack = '';
    host_lastboot = '';
	host_domain_role = '';
	host_system_type = '';
	host_timezone = '';
	host_current_domain_controller = '';
	host_registry_size = '';
	host_registry_size_max = '';
    host_manufacturer = '';
    host_model = '';
    host_physical_memory = '';
    host_assettag = '';
    host_serial_number = '';
    host_processor_name = '';
    host_processor_speed = '';
    host_processor_voltage = '';
	host_dns_cache = '';
    hostentries = @()
}

$InitStruct = New-Object PSObject -Property @{
    Output = 'Html';
    Logstash ='';
    Port = '';
	outputfolder = "\\$($AuditStruct.Hostname)\C$\Nagios\NAF\NAF_Reports";
	outputdate = (Get-Date -Format 'yyyyMMdd.HHmmss');
	outputfile = '';
	LogLocal = 'C:\Nagios\NAF\NAF_Logs\NAF_Actions.log';
	AdminGroupMembers = @();
	ObjGroupName = '';
    Services = '';
    ServiceHtmlSvcs = '';
    ServiceHtmlDisks = '';
    ServiceHtmlSharePerm = '';
    ShareObjs = @();
    ShareColl = '';
    ServiceHtmlShareNtfs = '';
    ShareNtfsObjs = @();
    ShareNtfsColl = '';
    NetwAdapHtml = '';
    RegHklm = '2147483650';
    SoftwareHtml = '';
    softwareobjs = @();
    dnscacheobjs = @();
	installedsoftreg = @();
    DnsCacheHtml = '';
	HostsHtml = ''
}

$WmiStruct = New-Object PSObject -Property @{
    Win32_OperatingSystem = '';
    Win32_Timezone = '';
    Win32_ComputerSystem = '';
    Win32_Registry = '';
    Win32_SystemEnclosure = '';
    Win32_Processor = '';
    Win32_NetworkadapterConfiguration = '';
    Win32_LogicalDisk = ''
}

$ErrorActionPreference = 'SilentlyContinue'
$DebugPreference = 'Continue'
$VerbosePreference = 'Continue'

Write-Log Verbose Info "Audit started on $($AuditStruct.hostname)."

#region Functions

function Test-FileLock {
      param ([parameter(Mandatory=$true)][string]$Path)
  $oFile = New-Object System.IO.FileInfo $Path
  try
  {
      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
      if ($oStream)
      {
        $oStream.Close()
      }
      return $false
  }
  catch
  {
    return $true
  }
}

function Write-Log {
    param (
	[parameter(Mandatory=$true)][string]$Log,
	[parameter(Mandatory=$true)][string]$Severity,
	[parameter(Mandatory=$true)][string]$Message
	)
	$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    if ($Log -eq 'Verbose') {
    	Write-Verbose "${Now}: ${Severity}: $Message"
    }
	elseif ($Log -eq 'Debug') {
    	Write-Debug "${Now}: ${Severity}: $Message"
    }
	elseif ($Log -eq 'Output') {
    	Write-Host "${Now}: ${Severity}: $Message"
    }
    else {
		if (!(Test-Path -Path $Log)){
			try {
				New-Item -Path $Log -Type file -Force | Out-null	
			}
			catch {
				$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
				Write-Host "${Now}: Error: Write-Log was unable to find or create the path `"$Log`". Please debug.."
				exit 1
			}
		}
        $Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
	    while (Test-FileLock $Log) {Start-Sleep (Get-Random -minimum 1 -maximum 10)}
	    "${Now}: ${Severity}: $Message" | Out-File -filepath $Log -Append
	}
}

function Get-WmiTrees {
    Write-Log Verbose Info 'WMI Querying started on $($AuditStruct.Hostname)...'
    Write-Log Verbose Info 'Querying Win32_OperatingSystem...'
    $WmiStruct.Win32_OperatingSystem = Get-WmiObject Win32_OperatingSystem -ComputerName $AuditStruct.Hostname
    Write-Log Verbose Info 'Querying Win32_Timezone...'
    $WmiStruct.Win32_Timezone = Get-WmiObject Win32_Timezone -computername $AuditStruct.Hostname 
    Write-Log Verbose Info 'Querying Win32_ComputerSystem...'
    $WmiStruct.Win32_ComputerSystem = Get-WmiObject Win32_ComputerSystem -computername $AuditStruct.Hostname
    Write-Log Verbose Info 'Querying Win32_Registry...'
    $WmiStruct.Win32_Registry = Get-WmiObject Win32_Registry -ComputerName $AuditStruct.Hostname
    Write-Log Verbose Info 'Querying Win32_SystemEnclosure...'
    $WmiStruct.Win32_SystemEnclosure = Get-WmiObject Win32_SystemEnclosure -ComputerName $AuditStruct.Hostname
    Write-Log Verbose Info 'Querying Win32_Processor...'
    $WmiStruct.Win32_Processor = Get-WmiObject Win32_Processor -ComputerName $AuditStruct.Hostname
    Write-Log Verbose Info 'Querying win32_NetworkadapterConfiguration...'
    $WmiStruct.Win32_NetworkadapterConfiguration = Get-WmiObject win32_NetworkadapterConfiguration -computername $AuditStruct.Hostname -Filter 'ipenabled = "true"'
    Write-Log Verbose Info 'Querying Win32_Logicaldisk...'
	$WmiStruct.Win32_LogicalDisk = Get-WmiObject Win32_Logicaldisk -ComputerName $AuditStruct.Hostname -Fi 'DriveType=3' | 
		Select-Object @{Name='Computername'; Expression={$_.SystemName}}, DeviceId,
		@{Name='SizeGB';Expression={'{0:N2}' -f ($_.Size/1GB)}},
		@{Name='FreeGB';Expression={'{0:N2}' -f ($_.Freespace/1GB)}},
		@{Name='UsedGB';Expression={'{0:N2}' -f (($_.Size-$_.FreeSpace)/1GB)}},
		@{Name='PerFree';Expression={'{0:P2}' -f ($_.FreeSpace/$_.Size)}}
    Write-Log Verbose Info 'WMI Querying end...'
}		
function Set-ProcessPriority { 
	param($ProcessName = $(throw 'Enter process name'), $Priority = 'Normal')
    Write-Log Verbose Info "Setting process priority of $ProcessName to $Priority..."
	Get-Process -processname $ProcessName | foreach { $_.PriorityClass = $Priority }
}
function Test-Paths { 
    Write-Log Verbose Info "Testing path for writing `"`b`b$($InitStruct.OutputFolder)\$($AuditStruct.Hostname)`.$($InitStruct.OutputDate).html`"..."
	$InitStruct.OutputFile = "\\$($InitStruct.OutputFolder)\$($AuditStruct.Hostname)`.$($InitStruct.OutputDate).html"
    if (!(Test-Path -path $InitStruct.OutputFolder)) {
        try {
			New-Item -Path $InitStruct.OutputFolder -Type directory -Force     
        }
        catch {
        	Write-Log Verbose Error "Cannot create directory `"`b`b$($InitStruct.OutputFolder)`" on $($AuditStruct.Hostname)"  
        }
        if (!(Test-Path -path $InitStruct.OutputFolder)) {
            Write-Log Verbose Error "directory `"`b`b$($InitStruct.OutputFolder)`" on $($AuditStruct.Hostname) was not created."        
        }
        else {
        	Write-Log Verbose Info "Directory `"`b`b$($InitStruct.OutputFolder)`" created on $($AuditStruct.Hostname)"   
        }
	}
}
Function Send-JsonOverTcp { 
 param ( [ValidateNotNullOrEmpty()] 
 [string] $NagiosLogServer, 
 [int] $Port, 
 $JsonObject) 
 $JsonString = $JsonObject -replace "`n",' ' -replace "`r",' '
 $Ip = [System.Net.Dns]::GetHostAddresses($NagiosLogServer) 
 $Address = [System.Net.IPAddress]::Parse($Ip) 
 $Socket = New-Object System.Net.Sockets.TCPClient($Address,$Port) 
 $Stream = $Socket.GetStream() 
 $Writer = New-Object System.IO.StreamWriter($Stream)
 $Writer.WriteLine($JsonString)
 $Writer.Flush()
 $Stream.Close()
 $Socket.Close()
}
function Get-HostEntries {
    [CmdletBinding()] 
    param (
		[Parameter(Mandatory=$false)][String]$Filter
	)
    function New-ObjectHostEntry{
        param(
            [string]$IP,
            [string]$DNS
        )
        New-Object PSObject -Property @{
            IP = $IP
            DNS = $DNS
        }
    }
    Write-Log Verbose Info 'Querying hosts file...'
    $Entries = $(get-content "$env:windir\System32\drivers\etc\hosts") | % {
        if (!$_.StartsWith('#') -and $_ -ne '') {
            $IP = ([regex]'(([2]([0-4][0-9]|[5][0-5])|[0-1]?[0-9]?[0-9])[.]){3}(([2]([0-4][0-9]|[5][0-5])|[0-1]?[0-9]?[0-9]))').match($_).value
            $DNS = ($_ -replace $IP, '') -replace  '\s+',''            
            if ($Filter -and (($IP -match $Filter) -or ($DNS -match $Filter))) {
                New-ObjectHostEntry -IP $IP -DNS $DNS
            }
            elseif ($Filter -eq '') {
                New-ObjectHostEntry -IP $IP -DNS $DNS
            }
        }  
    } 
    if ($Entries -ne $Null) {                
        $Entries      
    }
    else {
         Write-Log Verbose Info 'No entries found in host file...'
    }
    Write-Log Verbose Info 'Hosts file scanned.'
}

function Start-Audit {	
# Connectivity tests
	if ($AuditStruct.win_test_ping -eq '') {
    	$PingResult = Test-Connection -ComputerName $AuditStruct.Hostname -Count 1 -Quiet
	    if ($PingResult) {		
			$AuditStruct.win_test_ping = 'Succeeded'			
		} 
		else {
    		$AuditStruct.win_test_ping = 'Failed'
			Write-Host "CRITICAL: Ping to $Value failed! Please provide valid reachable hostname."
			exit 1
		}
	}
	Write-Log Verbose Info "Testing WMI on $($AuditStruct.Hostname)..."
 	$WmiTest = Get-WmiObject -Query "Select * from Win32_PingStatus where Address = '$($AuditStruct.Hostname)'"
	if($WmiTest) {
    	$AuditStruct.win_test_wmi = 'Succeeded'
	} 
	else {
    	$AuditStruct.win_test_wmi = 'Failed'
	}
	Write-Log Verbose Info "Testing Eventlog access on $($AuditStruct.Hostname)..."		
	$EventlogTest = Get-EventLog System -ComputerName $AuditStruct.Hostname -Newest 1
	if($EventlogTest) {
    	$AuditStruct.win_test_eventlog = 'Succeeded'
	} 
	else {
    	$AuditStruct.win_test_eventlog = 'Failed'
	}
# System information
	Write-Log Verbose Info 'Querying system information...'
    $AuditStruct.host_version = $WmiStruct.Win32_OperatingSystem.Version
    $AuditStruct.host_caption = $WmiStruct.Win32_OperatingSystem.Caption
    $AuditStruct.host_service_pack = $WmiStruct.Win32_OperatingSystem.ServicePackMajorVersion
	$AuditStruct.host_lastboot = ($WmiStruct.Win32_OperatingSystem.ConvertToDateTime($WmiStruct.Win32_OperatingSystem.LastBootUpTime)).ToString('dd/MM/yyyy HH:mm:ss')
	switch ($WmiStruct.Win32_ComputerSystem.DomainRole) {
		0 { $AuditStruct.host_domain_role = 'Standalone Workstation' }
		1 { $AuditStruct.host_domain_role = 'Member Workstation' }
		2 { $AuditStruct.host_domain_role = 'Standalone Server' }
		3 { $AuditStruct.host_domain_role = 'Member Server' }
		4 { $AuditStruct.host_domain_role = 'Domain Controller' }
		5 { $AuditStruct.host_domain_role = 'Domain Controller' }
		default { $AuditStruct.host_domain_role = 'Information not available' }
	}
    switch ($WmiStruct.Win32_ComputerSystem.PCSystemType) {
    	1 { $AuditStruct.host_system_type = 'Desktop' }
    	2 { $AuditStruct.host_system_type = 'Mobile / Laptop' }
    	3 { $AuditStruct.host_system_type = 'Workstation' }
 	    4 { $AuditStruct.host_system_type = 'Enterprise Server' }
   	 	5 { $AuditStruct.host_system_type = 'Small Office and Home Office (SOHO) Server' }
   	 	6 { $AuditStruct.host_system_type = 'Appliance PC' }
    	7 { $AuditStruct.host_system_type = 'Performance Server' }
    	8 { $AuditStruct.host_system_type = 'Maximum' }
    	default { $AuditStruct.host_system_type = 'Not a known Product Type' }
    } 
	$AuditStruct.host_timezone = $WmiStruct.Win32_Timezone.Description
	$AuditStruct.host_current_domain_controller = $env:LOGONSERVER -replace '\\', ''	
	$AuditStruct.host_registry_size = $WmiStruct.Win32_Registry.CurrentSize
	$AuditStruct.host_registry_size_max = $WmiStruct.Win32_Registry.MaximumSize
    if (!$AuditStruct.host_registry_size_max) {$AuditStruct.host_registry_size_max = 0}
	$AuditStruct.host_manufacturer = $WmiStruct.Win32_ComputerSystem.Manufacturer
	$AuditStruct.host_model = $WmiStruct.Win32_ComputerSystem.Model
	$AuditStruct.host_physical_memory = $WmiStruct.Win32_ComputerSystem.TotalPhysicalMemory
	$AuditStruct.host_assettag = $WmiStruct.Win32_SystemEnclosure.SMBIOSAssetTag
	$AuditStruct.host_serial_number = $WmiStruct.Win32_SystemEnclosure.SerialNumber
    $AuditStruct.host_processor_name = $WmiStruct.Win32_Processor.Name
    $AuditStruct.host_processor_speed = $WmiStruct.Win32_Processor.CurrentClockSpeed
    $AuditStruct.host_processor_voltage = $WmiStruct.Win32_Processor.CurrentVoltage
    foreach ($HostLogicalDisk in $WmiStruct.Win32_LogicalDisk) {
        $DrvDeviceId = ($HostLogicalDisk.DeviceId -replace ':','').tolower()
    	$AuditStruct | Add-Member -type NoteProperty -name win_drv_${DrvDeviceId}_name -Value $DrvDeviceId
        $AuditStruct | Add-Member -type NoteProperty -name win_drv_${DrvDeviceId}_totalgb -Value $HostLogicalDisk.SizeGB
        $AuditStruct | Add-Member -type NoteProperty -name win_drv_${DrvDeviceId}_freegb -Value $HostLogicalDisk.FreeGB
        $AuditStruct | Add-Member -type NoteProperty -name win_drv_${DrvDeviceId}_usedgb -Value $HostLogicalDisk.UsedGB
        $AuditStruct | Add-Member -type NoteProperty -name win_drv_${DrvDeviceId}_freeperc -Value $HostLogicalDisk.PerFree
    	$InitStruct.ServiceHtmlDisks += "<tr><td>$($HostLogicalDisk.DeviceId)</td><td>$($HostLogicalDisk.SizeGB) GB</td>	<td>$($HostLogicalDisk.FreeGB) GB</td><td>$($HostLogicalDisk.UsedGB) GB</td>	<td>$($HostLogicalDisk.PerFree)</td>	</tr>"
	}
# Administrator information
	Write-Log Verbose Info 'Querying administrators group members...'   
	$ObjSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
	$Objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
	$InitStruct.ObjGroupName = ($objgroup.Value).Split('\')[1]
	$AdsiGroup =[ADSI]"WinNT://$($AuditStruct.Hostname)/$($InitStruct.ObjGroupName)" 
	$InitStruct.AdminGroupMembers = @($AdsiGroup.psbase.Invoke('Members'))
# Service information
	Write-Log Verbose Info 'Querying system services...'
	$InitStruct.Services = Get-Service -ComputerName $AuditStruct.Hostname
	foreach ($service in $InitStruct.Services) {
		$StartupType = Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$($service.Name)'"      
        $servicelower = ($service.Name -replace '\s','').ToLower()
		$servicestate = "$($Service.Status)"
        $AuditStruct | Add-Member -type NoteProperty -name win_svc_${servicelower}_name -Value $service.DisplayName
        $AuditStruct | Add-Member -type NoteProperty -name win_svc_${servicelower}_status -Value $servicestate
        $AuditStruct | Add-Member -type NoteProperty -name win_svc_${servicelower}_startuptype -Value $StartupType.Startmode
        $InitStruct.ServiceHtmlSvcs += "<tr><td>$($service.Name)</td>
		<td>$($service.DisplayName)</td>
		<td>$servicestate</td>
		<td>$($StartupType.StartMode)</td>
		</tr>"   
	}
# Share information
	Write-Log Verbose Info 'Querying system share permissions...'   
	$InitStruct.ShareObjs = Get-SharedFolderPermission $AuditStruct.Hostname
	$LastShare = ''
	foreach ($ShareObj in $InitStruct.ShareObjs){
		$CurrentShare = ($ShareObj.SharedFolderName -replace '\s','').ToLower()
		if (($LastShare -eq '') -or ($CurrentSHare -eq $LastShare)) {
			$InitStruct.ShareColl += "{$($ShareObj.SharedFolderName) {$($ShareObj.SecurityPrincipal)},{$($ShareObj.FileSystemRights)},{$($ShareObj.AccessControlType)}}"
		}
		else {
			$AuditStruct | Add-Member -type NoteProperty -name win_share_$LastShare -Value $InitStruct.ShareColl
			$InitStruct.ShareColl = ''
			$InitStruct.ShareColl += "{$($ShareObj.SharedFolderName) {$($ShareObj.SecurityPrincipal)},{$($ShareObj.FileSystemRights)},{$($ShareObj.AccessControlType)}}"
		}
		$InitStruct.ServiceHtmlSharePerm +=	"<tr>
		<td>$($ShareObj.SharedFolderName)</td>
		<td>$($ShareObj.SecurityPrincipal)</td>
		<td>$($ShareObj.FileSystemRights)</td>
		<td>$($ShareObj.AccessControlType)</td>
		</tr>"
		$LastShare = $CurrentShare
	}
	$AuditStruct | Add-Member -type NoteProperty -name win_share_$LastShare -Value $InitStruct.ShareColl
# Share NTFS information
	Write-Log Verbose Info 'Querying share NTFS permissions...'   
	$InitStruct.ShareNtfsObjs = Get-SharedFolderNTFSPermission $AuditStruct.Hostname
	$LastShareNtfs = ''
	foreach ($ShareNtfsObj in $InitStruct.ShareNtfsObjs){
		$CurrentShareNtfs = ($ShareNtfsObj.SharedFolderName -replace '\s','_').ToLower()
		if (($LastShareNtfs -eq '') -or ($CurrentShareNtfs -eq $LastShareNtfs)) {
			$InitStruct.ShareNtfsColl += "{$($ShareNtfsObj.SharedFolderName) {$($ShareNtfsObj.SecurityPrincipal)},{$($ShareNtfsObj.FileSystemRights)},{$($ShareNtfsObj.AccessControlType)},{$($ShareNtfsObj.AccessControlFlags)}}"
		}
		else {
			$AuditStruct | Add-Member -type NoteProperty -name win_share_ntfs_$LastShareNtfs -Value $InitStruct.ShareNtfsColl
			$InitStruct.ShareNtfsColl = ''
			$InitStruct.ShareNtfsColl += "{$($ShareNtfsObj.SharedFolderName) {$($ShareNtfsObj.SecurityPrincipal)},{$($ShareNtfsObj.FileSystemRights)},{$($ShareNtfsObj.AccessControlType)},{$($ShareNtfsObj.AccessControlFlags)}}"
		}
		$InitStruct.ServiceHtmlShareNtfs +=	"<tr>
		<td>$($ShareNtfsObj.SharedFolderName)</td>
		<td>$($ShareNtfsObj.SecurityPrincipal)</td>
		<td>$($ShareNtfsObj.FileSystemRights)</td>
		<td>$($ShareNtfsObj.AccessControlType)</td>
		<td>$($ShareNtfsObj.AccessControlFlags)</td>
		</tr>"
		$LastShareNtfs = $CurrentShareNtfs
	}
	$AuditStruct | Add-Member -type NoteProperty -name win_share_ntfs_$LastShareNtfs -Value $InitStruct.ShareNtfsColl
# Network adapter information	
	Write-Log Verbose Info 'Querying system network adapters...'   
	foreach ($HostAdapter in $WmiStruct.Win32_NetworkadapterConfiguration) {
		$CurrentAdapter = ($HostAdapter.Description -replace '\s','_').ToLower()
		$AuditStruct | Add-Member -type NoteProperty -name win_nic_${CurrentAdapter}_name -Value $($HostAdapter.Description)
		$AuditStruct | Add-Member -type NoteProperty -name win_nic_${CurrentAdapter}_ips -Value $($HostAdapter.IPAddress)
		$AuditStruct | Add-Member -type NoteProperty -name win_nic_${CurrentAdapter}_dhcp -Value $($HostAdapter.DHCPEnabled)
		$AuditStruct | Add-Member -type NoteProperty -name win_nic_${CurrentAdapter}_subnet -Value $($HostAdapter.Subnet)
		$AuditStruct | Add-Member -type NoteProperty -name win_nic_${CurrentAdapter}_gateway -Value $($HostAdapter.DefaultIPGateway)
        $InitStruct.NetwAdapHtml +=	"<tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter IP Address</td>
		<td>$($HostAdapter.IPAddress)</td></tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter DHCP</td>
		<td>$($HostAdapter.DHCPEnabled)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter Subnet Mask</td>
		<td>$($HostAdapter.IPSubnet)</td>
		</tr></tbody>
		<tbody><tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter Gateway</td>
		<td>$($HostAdapter.DefaultIPGateway)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter MAC Address</td>
		<td>$($HostAdapter.MACAddress)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter DNS Servers</td>
		<td>$($HostAdapter.DNSServerSearchOrder)</td>
		</tr>"  
	}
# Software information	
	$Wmi = [wmiclass]"\\$($AuditStruct.Hostname)\root\default:stdRegProv"
	$RegClass = Get-WmiObject -Namespace 'Root\Default' -List -ComputerName $AuditStruct.Hostname | Where-Object { $_.Name -eq 'StdRegProv' }
	$IEKey = 'SOFTWARE\Microsoft\Internet Explorer'
	$IEVersion = ($regclass.GetStringValue($InitStruct.RegHklm,$IEKey,'Version')).sValue
	$InitStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'Internet Explorer'
								'Method'= 'Registry Microsoft\Internet Explorer Key'
				                'Version' = $IEVersion
				                'Vendor' = 'Microsoft'
				                'InstallDate' = 'unknown'}
	$McAfeeKey='SOFTWARE\McAfee\AVEngine'
	$McAfeeDATVersion = ($RegClass.GetDWORDValue($InitStruct.RegHklm,$McAfeeKey,'AVDATVersion')).uValue
	$McAfeeEngineVerMajor = ($RegClass.GetDWORDValue($InitStruct.RegHklm,$McAfeeKey,'EngineVersionMajor')).uValue
	$McAfeeEngineVerMinor = ($RegClass.GetDWORDValue($InitStruct.RegHklm,$McAfeeKey,'EngineVersionMinor')).uValue
	$InitStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'McAfee Antivirus DAT'
								'Method'= 'Registry McAfee\AVEngine Key'
				                'Version' = $McAfeeDATVersion
				                'Vendor' = 'McAfee'
				                'InstallDate' = 'unknown'
								}
	$InitStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'McAfee Antivirus Engine'
								'Method'= 'Registry McAfee\AVEngine Key'
				                'Version' = $McAfeeEngineVerMajor
				                'Vendor' = 'McAfee'
				                'InstallDate' = 'unknown'
								}
	$InitStruct.InstalledSoftReg = get-installedsoftware $AuditStruct.Hostname
	foreach ($InstalledSoftware in $InitStruct.InstalledSoftReg) {
		$InitStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = $InstalledSoftware.Name
								'Method'= 'Registry'
				                'Version' = $InstalledSoftware.Version
				                'Vendor' = $InstalledSoftware.Publisher
				                'InstallDate' = $InstalledSoftware.InstallDate
								'Size' = $InstalledSoftware.EstimatedSize
								}
	}
	$InitStruct.SoftwareObjs = $InitStruct.SoftwareObjs | Sort-Object Name, Method
	foreach ($SoftwareObj in $InitStruct.SoftwareObjs) {
		$CurrentSoftware = ($SoftwareObj.Name -replace '\s','_').ToLower()
		$AuditStruct | Add-Member -type NoteProperty -name win_prog_${CurrentSoftware}_name -Value "{{$($SoftwareObj.Name)}{$($SoftwareObj.Version)}{$($SoftwareObj.Size)}}"
		$InitStruct.SoftwareHtml += "<tr>
		<td>$($SoftwareObj.Name)</td>
		<td>$($SoftwareObj.Method)</td>
		<td>$($SoftwareObj.Version)</td>
		<td>$($SoftwareObj.Vendor)</td>
		<td>$($SoftwareObj.InstallDate)</td>
		<td>$($SoftwareObj.Size) MB</td>
		</tr>"
	}
# DNS Cache
	$InitStruct.DnsCacheObjs = Get-DNSClientCache
	foreach ($DnsCacheObj in $InitStruct.DnsCacheObjs) {
		$AuditStruct.host_dns_cache += "((Name:$($DnsCacheObj.Name))(Section:$($DnsCacheObj.Section))(TTL:$($DnsCacheObj.TTL))(Type:$($DnsCacheObj.Type))(Length:$($DnsCacheObj.Length))(Hostrecord:$($DnsCacheObj.HostRecord))) "
		$InitStruct.DnsCacheHtml += "<tr>
		<td>$($DnsCacheObj.Name)</td>
		<td>$($DnsCacheObj.Section)</td>
		<td>$($DnsCacheObj.TTL)</td>
		<td>$($DnsCacheObj.Type)</td>
		<td>$($DnsCacheObj.Length)</td>
		<td>$($DnsCacheObj.HostRecord)</td>
		</tr></tbody>"
	}

# Hosts File Entries
	$AuditStruct.HostEntries = Get-HostEntries
	foreach ($HostEntry in $AuditStruct.HostEntries) {
		$InitStruct.HostsHtml += "<tr>
		<td>$($HostEntry.IP)</td>
		<td>$($HostEntry.DNS)</td>
		</tr>"
	}
    $AuditStruct.audit_end = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss')
    $AuditDuration = New-TimeSpan –Start $AuditStruct.audit_start –End $AuditStruct.audit_end
    $AuditStruct.audit_duration = '{0:HH:mm:ss}' -f ([datetime]$AuditDuration.Ticks)   
}

Function Get-SharedFolderPermission {
    Param([String]$Computername)  
	$PingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
	if($PingResult)
	{
		if($Credential)
		{
			$SharedFolderSecs = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
		}
		else
		{
			$SharedFolderSecs = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -ComputerName $ComputerName -ErrorAction SilentlyContinue
		}
		
		foreach ($SharedFolderSec in $SharedFolderSecs) 
		{ 
		    $Objs = @() 				
	        $SecDescriptor = $SharedFolderSec.GetSecurityDescriptor()
	        foreach($DACL in $SecDescriptor.Descriptor.DACL)
			{  
				$DACLDomain = $DACL.Trustee.Domain
				$DACLName = $DACL.Trustee.Name
				if($DACLDomain -ne $null)
				{
	           		$UserName = "$DACLDomain\$DACLName"
				}
				else
				{
					$UserName = "$DACLName"
				}
				$Properties = @{'ComputerName' = $ComputerName
								'ConnectionStatus' = 'Success'
								'SharedFolderName' = $SharedFolderSec.Name
								'SecurityPrincipal' = $UserName
								'FileSystemRights' = [Security.AccessControl.FileSystemRights]$($DACL.AccessMask -as [Security.AccessControl.FileSystemRights])
								'AccessControlType' = [Security.AccessControl.AceType]$DACL.AceType}
				$SharedACLs = New-Object -TypeName PSObject -Property $Properties
				$Objs += $SharedACLs
	        }
			$Objs|Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType
	    }  
	}
	else
	{
		$Properties = @{'ComputerName' = $ComputerName
						'ConnectionStatus' = 'Fail'
						'SharedFolderName' = 'Not Available'
						'SecurityPrincipal' = 'Not Available'
						'FileSystemRights' = 'Not Available'
						'AccessControlType' = 'Not Available'}
		$SharedACLs = New-Object -TypeName PSObject -Property $Properties
		$Objs += $SharedACLs
		$Objs|Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType
	}
}

Function Get-SharedFolderNTFSPermission {
    Param([String]$Computername)  
	$PingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
	if($PingResult)
	{
		#check the credential whether trigger
		if($Credential)
		{
			$SharedFolders = Get-WmiObject -Class Win32_Share `
			-ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
		}
		else
		{
			$SharedFolders = Get-WmiObject -Class Win32_Share `
			-ComputerName $ComputerName -ErrorAction SilentlyContinue
		}

		foreach($SharedFolder in $SharedFolders)
		{
			$Objs = @()
			
			$SharedFolderPath = [regex]::Escape($SharedFolder.Path)
			if($Credential)
			{	
				$SharedNTFSSecs = Get-WmiObject -Class Win32_LogicalFileSecuritySetting `
				-Filter "Path='$SharedFolderPath'" -ComputerName $ComputerName  -Credential $Credential
			}
			else
			{
				$SharedNTFSSecs = Get-WmiObject -Class Win32_LogicalFileSecuritySetting `
				-Filter "Path='$SharedFolderPath'" -ComputerName $ComputerName
			}
			
			$SecDescriptor = $SharedNTFSSecs.GetSecurityDescriptor()
			foreach($DACL in $SecDescriptor.Descriptor.DACL)
			{  
				$DACLDomain = $DACL.Trustee.Domain
				$DACLName = $DACL.Trustee.Name
				if($DACLDomain -ne $null)
				{
	           		$UserName = "$DACLDomain\$DACLName"
				}
				else
				{
					$UserName = "$DACLName"
				}
				
				#customize the property
				$Properties = @{'ComputerName' = $ComputerName
								'ConnectionStatus' = 'Success'
								'SharedFolderName' = $SharedFolder.Name
								'SecurityPrincipal' = $UserName
								'FileSystemRights' = [Security.AccessControl.FileSystemRights]$($DACL.AccessMask -as [Security.AccessControl.FileSystemRights])
								'AccessControlType' = [Security.AccessControl.AceType]$DACL.AceType
								'AccessControlFlags' = [Security.AccessControl.AceFlags]$DACL.AceFlags}
								
				$SharedNTFSACL = New-Object -TypeName PSObject -Property $Properties
	            $Objs += $SharedNTFSACL
	        }
			$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType,AccessControlFlags -Unique
		}
	}
	else
	{
		$Properties = @{'ComputerName' = $ComputerName
						'ConnectionStatus' = 'Fail'
						'SharedFolderName' = 'Not Available'
						'SecurityPrincipal' = 'Not Available'
						'FileSystemRights' = 'Not Available'
						'AccessControlType' = 'Not Available'
						'AccessControlFlags' = 'Not Available'}
					
		$SharedNTFSACL = New-Object -TypeName PSObject -Property $Properties
	    $Objs += $SharedNTFSACL
		$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType,AccessControlFlags -Unique
	}
} 

Function Get-InstalledSoftware{ 
    Param([String[]]$Computers)  
    If (!$Computers) {$Computers = $ENV:ComputerName} 
    $Base = New-Object PSObject; 
    $Base | Add-Member Noteproperty ComputerName -Value $Null; 
    $Base | Add-Member Noteproperty Name -Value $Null; 
    $Base | Add-Member Noteproperty Publisher -Value $Null; 
    $Base | Add-Member Noteproperty InstallDate -Value $Null; 
    $Base | Add-Member Noteproperty EstimatedSize -Value $Null; 
    $Base | Add-Member Noteproperty Version -Value $Null; 
    $Base | Add-Member Noteproperty Wow6432Node -Value $Null; 
    $Results =  New-Object System.Collections.Generic.List[System.Object]; 
 
    ForEach ($ComputerName in $Computers){ 
        $Registry = $Null; 
        Try{$Registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$ComputerName);} 
        Catch{Write-Host -ForegroundColor Red "$($_.Exception.Message)";} 	         
        If ($Registry){ 
            $UninstallKeys = $Null; 
            $SubKey = $Null; 
            $UninstallKeys = $Registry.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Uninstall',$False); 
            $UninstallKeys.GetSubKeyNames()|%{ 
                $SubKey = $UninstallKeys.OpenSubKey($_,$False); 
                $DisplayName = $SubKey.GetValue('DisplayName'); 
                If ($DisplayName.Length -gt 0){ 
                    $Entry = $Base | Select-Object * 
                    $Entry.ComputerName = $ComputerName; 
                    $Entry.Name = $DisplayName.Trim();  
                    $Entry.Publisher = $SubKey.GetValue('Publisher');  
                    [ref]$ParsedInstallDate = Get-Date                     
                    $Entry.InstallDate = $SubKey.GetValue('InstallDate') 	                    
                    $Entry.EstimatedSize = [Math]::Round($SubKey.GetValue('EstimatedSize')/1KB,1); 
                    $Entry.Version = $SubKey.GetValue('DisplayVersion'); 
                    [Void]$Results.Add($Entry); 
                } 
            } 
             
                If ([IntPtr]::Size -eq 8){ 
                $UninstallKeysWow6432Node = $Null; 
                $SubKeyWow6432Node = $Null; 
                $UninstallKeysWow6432Node = $Registry.OpenSubKey('Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall',$False); 
                    If ($UninstallKeysWow6432Node) { 
                        $UninstallKeysWow6432Node.GetSubKeyNames()|%{ 
                        $SubKeyWow6432Node = $UninstallKeysWow6432Node.OpenSubKey($_,$False); 
                        $DisplayName = $SubKeyWow6432Node.GetValue('DisplayName'); 
                        If ($DisplayName.Length -gt 0){ 
                            $Entry = $Base | Select-Object * 
                            $Entry.ComputerName = $ComputerName; 
                            $Entry.Name = $DisplayName.Trim();  
                            $Entry.Publisher = $SubKeyWow6432Node.GetValue('Publisher');  
                            [ref]$ParsedInstallDate = Get-Date                      
                            $Entry.InstallDate = $SubKeyWow6432Node.GetValue('InstallDate')
                            $Entry.EstimatedSize = [Math]::Round($SubKeyWow6432Node.GetValue('EstimatedSize')/1KB,1); 
                            $Entry.Version = $SubKeyWow6432Node.GetValue('DisplayVersion'); 
                            $Entry.Wow6432Node = $True; 
                            [Void]$Results.Add($Entry); 
                            } 
                        } 
                    } 
                } 
	        } 
	    } 
	    $Results 
}
Function Get-DNSClientCache{ 
	$DNSCache = @() 
	Invoke-Expression 'IPConfig /DisplayDNS' | 
	Select-String -Pattern 'Record Name' -Context 0,5 | 
	    %{ 
	        $Record = New-Object PSObject -Property @{ 
	        Name=($_.Line -Split ':')[1] 
	        Type=($_.Context.PostContext[0] -Split ':')[1] 
	        TTL=($_.Context.PostContext[1] -Split ':')[1] 
	        Length=($_.Context.PostContext[2] -Split ':')[1] 
	        Section=($_.Context.PostContext[3] -Split ':')[1] 
	        HostRecord=($_.Context.PostContext[4] -Split ':')[1] 
	        } 
	        $DNSCache +=$Record 
	    } 
	    return $DNSCache 
}
Function Initialize-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args
    )
	
    try {
        For ( $i = 0; $i -lt $Args.count; $i++ ) { 
		    $CurrentArg = $Args[$i].ToString()
            if ($i -lt $Args.Count-1) {
				$Value = $Args[$i+1];
				If ($Value.Count -ge 2) {
					foreach ($Item in $Value) {
						Test-Strings $Item | Out-Null
					}
				}
				else {
	                $Value = $Args[$i+1];
					Test-Strings $Value | Out-Null
				}	                             
            } else {
                $Value = ''
            };

            switch -regex -casesensitive ($CurrentArg) {
                "^(-H|--Hostname)$" {
					if ($Value -ne ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower() -and $Value -ne 'localhost') {
						$PingResult = Test-Connection -ComputerName $Value -Count 1 -Quiet
						if ($PingResult) {			
							$AuditStruct.Hostname = $Value
							$AuditStruct.win_test_ping = 'Succeeded'
							$i++						
		    			} 
						else {
    						$AuditStruct.win_test_ping = 'Failed'
		    				Write-Host "CRITICAL: Ping to $Value failed! Please provide valid reachable hostname."
							exit 1
		    			}
					}
					else {
						$AuditStruct.Hostname = $Value
						$i++
					}
						
                }
                "^(-O|--Output)$" {
                    if (($value -match 'Html' -or $value -match 'Logstash')) {
                        $InitStruct.Output = $value
                    } else {
                        throw "Some issue with output value. Value given is $value."
                    }
                    $i++
                 }
                "^(-L|--Logstash)$" {
                    if ($value -match "^[a-zA-Z0-9_.]+$") {
                        $InitStruct.Logstash = $value
                    } else {
                        throw "Some issues with logstash server value. Value given is $value."
                    }
                    $i++
                 }
          		"^(-p|--Port)$" {
                    if (($value -match "^[0-9]+$")-and ([int]$value -lt 65000)) {
                        $InitStruct.port = $value
                    } else {
                        throw "Some issues with port value. Value given is $value."
                    }
                    $i++
                 }

                "^(-h|--Help)$" {
                    Write-Help
                }
                default {
                    throw "Illegal arguments detected: $_"
                }
            }
        }
    } catch {
		Write-Host "UNKNOWN: $_"
        Exit 2
	}

}
Function Test-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host 'Unknown: String contains illegal characters.'
            Exit 2
        }
    }
    Return $true
} 
Function Write-Help {
	Write-Host @"
naf_initiate_ms_server_audit.ps1:
This script is designed to audit a MS server and output result to html.
Arguments:
    -H  | --Hostname     => Optional hostname of remote system, default is localhost, not yet tested on remote host.
    -O  | --Output  		 => Audit output, currently to html and to Logstash or equivalents
    -L  | --Logstash     => Logstash server to send audit to
    -p  | --Port			 => Logstash server port to send audit to
    -h  | --Help         => Print this help output.
"@
    Exit 3
} 


#endregion Functions


# Main

if($Args.count -ge 1){
	Initialize-Args $Args
}
Test-Paths
Get-WmiTrees
Start-Audit

# Write-Host $AuditJson

if ($InitStruct.Output -eq 'Html') {
    Write-Log Verbose Info "Starting Html output. Initiating write to $($InitStruct.OutputFile)..."
    	"<!DOCTYPE html>
	<html>
	<head>
	<meta charset=""utf-8"">
	<meta name=""description"" content=""This generated html page will display available information for the server passed as a parameter."">
	<style type=""text/css"">
	table {
	    border: 5px solid grey ;
	}
	th, td {
		padding: 5px 10px;
		border: 1px solid #999;
		text-align: left;
	}
	th {
	    background-color: #eee;
	}
	</style>
	</head>
	<body>
	<h1>NAF - Server Audit</h1>
	<br><hr>
    <h3>Audit information</h3>
	<table><thead><tr>
	<th>Start Date</th>
	<th>End Date</th>
	<th>Duration</th>
	<th>Executer</th>
	</tr></thead>
	<tbody><tr>
	<td>$($AuditStruct.audit_start)</td>
	<td>$($AuditStruct.audit_end)</td>
	<td>$($AuditStruct.audit_duration)</td>
	<td>$($AuditStruct.audit_executer)</td>
	</tr></tbody>
	</table>
	<br><hr>
	<h3>Connectivity Test</h3> 
	<table><thead><tr>
	<th>Test</th>
	<th>Result</th>
	</tr></thead>
	<tbody><tr>
	<td>Ping</td>
	<td>$($AuditStruct.win_test_ping)</td>
	</tr></tbody>
	<tbody><tr>
	<td>WMI</td>
	<td>$($AuditStruct.win_test_wmi)</td>
	</tr></tbody>
	<tbody><tr>
	<td>Eventlog</td>
	<td>$($AuditStruct.win_test_eventlog)</td>
	</tr></tbody>
	</table>
	<br><hr>
	<h3>System Information</h3>
	<table>
	<thead><tr><th>Query</th><th>Result</th></tr></thead>
	<tbody><tr><td>System Version </td><td>$($AuditStruct.host_version)</td></tr></tbody>
	<tbody><tr><td>System Caption </td><td>$($AuditStruct.host_caption)</td></tr></tbody>
	<tbody><tr><td>System Service Pack </td><td>$($AuditStruct.host_service_pack)</td></tr></tbody>
	<tbody><tr><td>System Last Boot </td><td>$($AuditStruct.host_lastboot)</td></tr></tbody>
	<tbody><tr><td>System Domain Role </td><td>$($AuditStruct.host_domain_role)</td></tr></tbody>
	<tbody><tr><td>System Type </td><td>$($AuditStruct.host_system_type)</td></tr></tbody>
	<tbody><tr><td>System Time Zone </td><td>$($AuditStruct.host_timezone)</td></tr></tbody>
	<tbody><tr><td>System Domain Controller</td><td>$($AuditStruct.host_current_domain_controller)</td></tr></tbody>
	<tbody><tr><td>System Current Registry Size</td><td>$($AuditStruct.host_registry_size)</td></tr></tbody>
	<tbody><tr><td>System Maximum Registry Size</td><td>$($AuditStruct.host_registry_size_max)</td></tr></tbody>
	<tbody><tr><td>System Manufacturer</td><td>$($AuditStruct.host_manufacturer)</td></tr></tbody>
	<tbody><tr><td>System Model</td><td>$($AuditStruct.host_model)</td></tr></tbody>
	<tbody><tr><td>System Total Physical Memory</td><td>$($AuditStruct.host_physical_memory)</td></tr></tbody>
	<tbody><tr><td>System Asset Tag</td><td>$($AuditStruct.host_assettag)</td></tr></tbody>
	<tbody><tr><td>System Serial Number</td><td>$($AuditStruct.host_serial_number)</td></tr></tbody>
	<tbody><tr><td>System Processor Name</td><td>$($AuditStruct.host_processor_name)</td></tr></tbody>
	<tbody><tr><td>System Processor Speed</td><td>$($AuditStruct.host_processor_speed)</td></tr></tbody>
	<tbody><tr><td>System Processor Voltage</td><td>$($AuditStruct.host_processor_voltage)</td></tr></tbody>
	</table>
	<br>	<hr>
	<h3>Disk Information</h3>
	<table><thead><tr>
	<th>Drive Name</th>
	<th>Total Size (GB)</th>
	<th>Free GB</th><th>Used GB</th>
	<th>Percentage Free</th>
	</tr></thead>
    <tbody>
	$($InitStruct.ServiceHtmlDisks)
    </tbody>
	</table>
	<br><hr>
	<h3>Local Group Members</h3>
	<table><thead><tr>
	<th>Group Name</th>
	<th>Group Members</tr>
	</thead>" | out-file -Append $InitStruct.OutputFile
	$InitStruct.AdminGroupMembers | foreach {
	 	$obj = new-object psobject -Property @{LocalAdmin = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)}
	 	"<tbody><tr>
		<td>$($InitStruct.ObjGroupName)</td>
		<td>$($obj.LocalAdmin)</td>
		</tr></tbody>" | out-file -Append $InitStruct.OutputFile
	} 
	"</table><br><hr>
    <h3>Service Configuration</h3>
	<table><thead><tr>
	<th>Service Name</th>
	<th>Display Name</th><th>Status</th>
	<th>Startup Type</th>
	</tr></thead><tbody>
    $($InitStruct.ServiceHtmlSvcs)
    </tbody></table><br><hr>
    <h3>Share Permissions</h3>
	<table><thead><tr><th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	</tr></thead>
	<tbody>
	$($InitStruct.ServiceHtmlSharePerm)
	</tobdy>
	</table><br><hr>
	<h3>Share NTFS Permissions</h3>
	<table><thead><tr>
	<th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	<th>Access Control Flags</th>
	</tr></thead>
	<tbody>
	$($InitStruct.ServiceHtmlShareNtfs)
	</tbody>
	</table><br><hr>
	<h3>Network Adapters</h3>
	<table><thead><tr>
	<th>Adapter Name</th>
	<th>Adapter Query</th>
	<th>Adapter Query Result</th>
	</tr></thead>
	<tbody>
	$($InitStruct.NetwAdapHtml)
	</tbody>
	</table><br><hr>
	<h3>Software Information</h3>
	<table><thead><tr>
	<th>Software Name</th>
	<th>Method</th>
	<th>Version</th>
	<th>Vendor</th>
	<th>Install Date</th>
	<th>Estimated Size</th>
	</tr></thead><tbody>
	$($InitStruct.SoftwareHtml)
	</tbody></table><br><hr>
	<h3>DNS Cache</h3>
	<table><thead><tr>
	<th>Name</th>
	<th>Section</th>
	<th>TTL</th>
	<th>Type</th>
	<th>Length</th>
	<th>Host Record</th>
	</tr></thead><tbody>
	$($InitStruct.DnsCacheHtml)
	</tbody>
	</table><br><hr>
	<h4>Hosts file</h3>
	<table><thead><tr>
	<th>IP</th>
	<th>DNS</th>
	</tr></thead>
	<tbody>
	$($InitStruct.HostsHtml)	
	</tbody>
	</table><br><hr>
	</html>" | out-file -append $InitStruct.OutputFile
}
if ($InitStruct.Output -eq 'Logstash') {
    Write-Log Verbose Info 'Starting Logstash output. Initiating Json conversion...'
    try {
    	$AuditJson = $AuditStruct | ConvertTo-Json
    }
    catch {
        Write-Log Output Error 'Json conversion failed. Please debug...'
    }
    Write-Log Verbose Info 'Json conversion successful.'

    Write-Log Verbose Info 'Initiating Send-JsonOverTcp over port $($InitStruct.Port).'
    try {
    	Send-JsonOverTcp $InitStruct.Logstash $InitStruct.Port $Auditjson
    }
    catch {
        Write-Log Output Error 'Send-JsonOverTcp over port $($InitStruct.Port) failed. Please debug...'
    }
	Write-Log Verbose Info 'Send-JsonOverTcp over port $($InitStruct.Port) finished successfully.'
}

Write-Log Output Info "OK: Audit of $($AuditStruct.Hostname) succeeded in $($AuditStruct.audit_duration) time."
exit 0