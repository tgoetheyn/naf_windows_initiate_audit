# Script name:   	naf_initiate_ms_server_audit.ps1
# Version:			v1.6.11
# Created on:    	15/09/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Initiates audit of Microsoft server
# On Github:		https://github.com/willemdh/naf_initiate_ms_server_audit
# On OutsideIT:		http://outsideit.net/naf-initiate-ms-server-audit
# Recent History:       	
#	07/06/2015 => Added host record entries and cleanup
#	08/06/2015 => Splitted WMI queries to different stucture, preparing for output to json
#	09/06/2015 => Fixed duration and added exitcode with output
#	10/06/2015 => First step to multiple outputs
#	11/06/2015 => Fixed admin and disk html
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 2.0

$AuditStruct = New-Object PSObject -Property @{
    startdatetime = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'); 
    executer = ("$ENV:USERDOMAIN\$ENV:USERNAME")
    hostname = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower();	
	outputdate = (Get-Date -Format 'yyyyMMdd.HHmmss');
	exitcode = 3;
    pingtest = 0;
    wmitest = 0;
    eventlogtest = 0;
    hostversion ='';
    hostcaption = '';
    hostservicepackmajorversion = '';
    hostlastboot = '';
    hostsystemdirectory = '';
	hostdomainrole = '';
	hostsystemtype = '';
	hosttimezone = '';
	hostcurrentdomaincontroller = '';
	hostregistrycursize = '';
	hostregistrymaxsize = '';
    hostmanufacturer = '';
    hostmodel = '';
    hostphysicalmemory = '';
    hostassettag = '';
    hostserialnumber = '';
    hostprocessorname = '';
    hostprocessorspeed = '';
    hostprocessorvoltage = '';
    hostprocessorload = '';
	hostlogicaldisks = '';
	hostadapters = @();
	hostcurregsize = '';
	hostmaxregsize = '';
	hostprocessor = '';
	services = @();
	shareobjs = @();
	sharentfsobjs = @();
	installedsoftreg = @();
	softwareobjs = @();
	dnscacheobjs = @();
    hostentries = @();
    enddatetime = '';
    auditduration = ''
}

$InitStruct = New-Object PSObject -Property @{
    Output = '';
    Logstash ='';
    Port = '';
	outputfolder = "\\$($AuditStruct.Hostname)\C$\Nagios\NAF\NAF_Logs\Reports";
	outputfile = '';
	AdminGroupMembers = @();
	ObjGroupName = ''
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

Write-Log Verbose "Audit started on $($AuditStruct.hostname)."

#region Functions

function Test-FileLock {
      param ([parameter(Mandatory=$true)][string]$Path)

  $oFile = New-Object System.IO.FileInfo $Path

  if ((Test-Path -Path $Path) -eq $false)
  {
    return $false
  }
  try
  {
      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
      if ($oStream)
      {
        $oStream.Close()
      }
      $false
  }
  catch
  {
    # file is locked by a process.
    return $true
  }
}
function Write-Log {
    param (
	[parameter(Mandatory=$true)][string]$Log,
	[parameter(Mandatory=$true)][string]$Message
	)
	$Now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss,fff'
    If ($Log -eq 'Verbose') {
    	Write-Verbose "${Now}: $Message"
    }
    else {
        $Date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
	    while (Test-FileLock $Log) {Start-Sleep (Get-Random -minimum 1 -maximum 10)}
	    "${Now}: $Message" | Out-File -filepath $Log -Append
    }
}
function Get-WmiTrees {
    Write-Log Verbose 'WMI Querying started on $($AuditStruct.Hostname)...'
    Write-Log Verbose 'Querying Win32_OperatingSystem...'
    $WmiStruct.Win32_OperatingSystem = Get-WmiObject Win32_OperatingSystem -ComputerName $AuditStruct.Hostname
    Write-Log Verbose 'Querying Win32_Timezone...'
    $WmiStruct.Win32_Timezone = Get-WmiObject Win32_Timezone -computername $AuditStruct.Hostname 
    Write-Log Verbose 'Querying Win32_ComputerSystem...'
    $WmiStruct.Win32_ComputerSystem = Get-WmiObject Win32_ComputerSystem -computername $AuditStruct.Hostname
    Write-Log Verbose 'Querying Win32_Registry...'
    $WmiStruct.Win32_Registry = Get-WmiObject Win32_Registry -ComputerName $AuditStruct.Hostname
    Write-Log Verbose 'Querying Win32_SystemEnclosure...'
    $WmiStruct.Win32_SystemEnclosure = Get-WmiObject Win32_SystemEnclosure -ComputerName $AuditStruct.Hostname
    Write-Log Verbose 'Querying Win32_Processor...'
    $WmiStruct.Win32_Processor = Get-WmiObject Win32_Processor -ComputerName $AuditStruct.Hostname
    Write-Log Verbose 'Querying win32_NetworkadapterConfiguration...'
    $WmiStruct.Win32_NetworkadapterConfiguration = Get-WmiObject win32_NetworkadapterConfiguration -computername $AuditStruct.Hostname -Filter 'ipenabled = "true"'
    Write-Log Verbose 'Querying Win32_Logicaldisk...'
	$WmiStruct.Win32_LogicalDisk = Get-WmiObject Win32_Logicaldisk -ComputerName $AuditStruct.Hostname -Fi 'DriveType=3' | 
		Select-Object @{Name='Computername'; Expression={$_.SystemName}}, DeviceId,
		@{Name='SizeGB';Expression={'{0:N2}' -f ($_.Size/1GB)}},
		@{Name='FreeGB';Expression={'{0:N2}' -f ($_.Freespace/1GB)}},
		@{Name='UsedGB';Expression={'{0:N2}' -f (($_.Size-$_.FreeSpace)/1GB)}},
		@{Name='PerFree';Expression={'{0:P2}' -f ($_.FreeSpace/$_.Size)}}
    Write-Log Verbose 'WMI Querying end...'
}		
function Set-ProcessPriority { 
	param($ProcessName = $(throw 'Enter process name'), $Priority = 'Normal')
    Write-Log Verbose "Setting process priority of $ProcessName to $Priority..."
	Get-Process -processname $ProcessName | foreach { $_.PriorityClass = $Priority }
}
function Test-Paths { 
    Write-Log Verbose "Testing path for writing `"`b`b$($InitStruct.OutputFolder)\$($AuditStruct.Hostname)`.$($AuditStruct.OutputDate).html`"..."
	$InitStruct.OutputFile = "\\$($InitStruct.OutputFolder)\$($AuditStruct.Hostname)`.$($AuditStruct.OutputDate).html"
    if (!(Test-Path -path $InitStruct.OutputFolder)) {
        try {
			New-Item -Path $InitStruct.OutputFolder -Type directory -Force     
        }
        catch {
        	Write-Log Verbose "Error creating directory `"`b`b$($InitStruct.OutputFolder)`" on $($AuditStruct.Hostname)"  
        }
        if (!(Test-Path -path $InitStruct.OutputFolder)) {
            Write-Log Verbose "Error creating directory `"`b`b$($InitStruct.OutputFolder)`" on $($AuditStruct.Hostname)"        
        }
        else {
        	Write-Log Verbose "Directory `"`b`b$($InitStruct.OutputFolder)`" created on $($AuditStruct.Hostname)"   
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
    Write-Log Verbose 'Querying hosts file...'
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
         Write-Log Verbose 'No entries found in host file...'
    }
    Write-Log Verbose 'Hosts file scanned.'
}

function Start-Audit {	
	if ($AuditStruct.PingTest -eq '') {
    	$PingResult = Test-Connection -ComputerName $AuditStruct.Hostname -Count 1 -Quiet
	    if ($PingResult) {		
			$AuditStruct.PingTest = 'Succeeded'			
		} 
		else {
    		$AuditStruct.PingTest = 'Failed'
			Write-Host "CRITICAL: Ping to $Value failed! Please provide valid reachable hostname."
			exit 1
		}
	}
	Write-Log Verbose "Testing WMI on $($AuditStruct.Hostname)..."
 	$WmiTest = Get-WmiObject -Query "Select * from Win32_PingStatus where Address = '$($AuditStruct.Hostname)'"
	if($WmiTest) {
    	$AuditStruct.WmiTest = 'Succeeded'
	} 
	else {
    	$AuditStruct.WmiTest = 'Failed'
	}
	Write-Log Verbose "Testing Eventlog access on $($AuditStruct.Hostname)..."		
	$EventlogTest = Get-EventLog System -ComputerName $AuditStruct.Hostname -Newest 1
	if($EventlogTest) {
    	$AuditStruct.EventlogTest = 'Succeeded'
	} 
	else {
    	$AuditStruct.EventlogTest = 'Failed'
	}
	Write-Log Verbose 'Querying system information...'
    $AuditStruct.HostVersion = $WmiStruct.Win32_OperatingSystem.Version
    $AuditStruct.HostCaption = $WmiStruct.Win32_OperatingSystem.Caption
    $AuditStruct.HostServicePackMajorVersion = $WmiStruct.Win32_OperatingSystem.ServicePackMajorVersion
	$AuditStruct.HostLastBoot = ($WmiStruct.Win32_OperatingSystem.ConvertToDateTime($WmiStruct.Win32_OperatingSystem.LastBootUpTime)).ToString('dd/MM/yyyy HH:mm:ss')
    $AuditStruct.HostSystemDirectory = $WmiStruct.Win32_OperatingSystem.SystemDirectory
	switch ($WmiStruct.Win32_ComputerSystem.DomainRole) {
		0 { $AuditStruct.HostDomainRole = 'Standalone Workstation' }
		1 { $AuditStruct.HostDomainRole = 'Member Workstation' }
		2 { $AuditStruct.HostDomainRole = 'Standalone Server' }
		3 { $AuditStruct.HostDomainRole = 'Member Server' }
		4 { $AuditStruct.HostDomainRole = 'Domain Controller' }
		5 { $AuditStruct.HostDomainRole = 'Domain Controller' }
		default { $AuditStruct.HostDomainRole = 'Information not available' }
	}
    switch ($WmiStruct.Win32_ComputerSystem.PCSystemType) {
    	1 { $AuditStruct.HostSystemType = 'Desktop' }
    	2 { $AuditStruct.HostSystemType = 'Mobile / Laptop' }
    	3 { $AuditStruct.HostSystemType = 'Workstation' }
 	    4 { $AuditStruct.HostSystemType = 'Enterprise Server' }
   	 	5 { $AuditStruct.HostSystemType = 'Small Office and Home Office (SOHO) Server' }
   	 	6 { $AuditStruct.HostSystemType = 'Appliance PC' }
    	7 { $AuditStruct.HostSystemType = 'Performance Server' }
    	8 { $AuditStruct.HostSystemType = 'Maximum' }
    	default { $AuditStruct.HostSystemType = 'Not a known Product Type' }
    } 
	$AuditStruct.HostTimeZone = $WmiStruct.Win32_Timezone.Description
	$AuditStruct.HostCurrentDomainController = $env:LOGONSERVER -replace '\\', ''	
	$AuditStruct.HostRegistryCurSize = $WmiStruct.Win32_Registry.CurrentSize
	$AuditStruct.HostRegistryMaxSize = $WmiStruct.Win32_Registry.MaximumSize
    if (!$AuditStruct.HostRegistryMaxSize) {$AuditStruct.HostRegistryMaxSize = 'Undefined'}
	$AuditStruct.HostManufacturer = $WmiStruct.Win32_ComputerSystem.Manufacturer
	$AuditStruct.HostModel = $WmiStruct.Win32_ComputerSystem.Model
	$AuditStruct.HostPhysicalMemory = $WmiStruct.Win32_ComputerSystem.TotalPhysicalMemory
	$AuditStruct.HostAssetTag = $WmiStruct.Win32_SystemEnclosure.SMBIOSAssetTag
	$AuditStruct.HostSerialNumber = $WmiStruct.Win32_SystemEnclosure.SerialNumber
    $AuditStruct.HostProcessorName = $WmiStruct.Win32_Processor.Name
    $AuditStruct.HostProcessorSpeed = $WmiStruct.Win32_Processor.CurrentClockSpeed
    $AuditStruct.HostProcessorVoltage = $WmiStruct.Win32_Processor.CurrentVoltage
    $AuditStruct.HostProcessorLoad = $WmiStruct.Win32_Processor.LoadPercentage
	Write-Log Verbose 'Querying administrators group members...'   
	$ObjSID = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
	$Objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
	$InitStruct.ObjGroupName = ($objgroup.Value).Split('\')[1]
	$AdsiGroup =[ADSI]"WinNT://$($AuditStruct.Hostname)/$($InitStruct.ObjGroupName)" 
	$InitStruct.AdminGroupMembers = @($AdsiGroup.psbase.Invoke('Members'))

	'<h3>Service Configuration</h3>
	<table><thead><tr>
	<th>Service Name</th>
	<th>Display Name</th><th>Status</th>
	<th>Startup Type</th>
	</tr></thead>' | out-file -Append $AuditStruct.OutputFile
	Write-Log Verbose 'Querying system services...'
	$AuditStruct.Services = Get-Service -ComputerName $AuditStruct.Hostname
	foreach ($service in $AuditStruct.Services) {
		$StartupType = Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$($service.Name)'"
	    "<tbody><tr><td>$($service.Name)</td>
		<td>$($service.DisplayName)</td>
		<td>$($service.Status)</td>
		<td>$($StartupType.StartMode)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile		   
	}
	'</table><br><hr>' | Out-File -Append $AuditStruct.OutputFile
	Write-Log Verbose 'Querying system share permissions...'   
	'<h3>Share Permissions</h3>
	<table><thead><tr><th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile

	$AuditStruct.ShareObjs = Get-SharedFolderPermission $AuditStruct.Hostname
	foreach ($ShareObj in $AuditStruct.ShareObjs){
		"<tbody><tr>
		<td>$($ShareObj.SharedFolderName)</td>
		<td>$($ShareObj.SecurityPrincipal)</td>
		<td>$($ShareObj.FileSystemRights)</td>
		<td>$($ShareObj.AccessControlType)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}
	'</table><br><hr>' | Out-File -Append $AuditStruct.OutputFile
	Write-Log Verbose 'Querying share NTFS permissions...'   
	'<h3>Share NTFS Permissions</h3>
	<table><thead><tr>
	<th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	<th>Access Control Flags</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile
	$AuditStruct.ShareNtfsObjs = Get-SharedFolderNTFSPermission $AuditStruct.Hostname
	foreach ($ShareNtfsObj in $AuditStruct.ShareNtfsObjs){
		"<tbody><tr>
		<td>$($ShareNtfsObj.SharedFolderName)</td>
		<td>$($ShareNtfsObj.SecurityPrincipal)</td>
		<td>$($ShareNtfsObj.FileSystemRights)</td>
		<td>$($ShareNtfsObj.AccessControlType)</td>
		<td>$($ShareNtfsObj.AccessControlFalgs)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}
	'</table><br><hr>' | Out-File -Append $AuditStruct.OutputFile
	Write-Log Verbose 'Querying system network adapters...'   
	'<h3>Network Adapters</h3>
	<table><thead><tr>
	<th>Hostname</th>
	<th>Adapter Name</th>
	<th>Adapter Query</th>
	<th>Adapter Query Result</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile
	foreach ($HostAdapter in $WmiStruct.Win32_NetworkadapterConfiguration) {
        $HostAdapObj = New-Object PSObject -Property @{
            DnsHostName = $HostAdapter.DNSHostName;
            Description = $HostAdapter.Description;
            IpAddress = $HostAdapter.IPAddress;
            DhcpEnabled = $HostAdapter.DHCPEnabled
        }
        $AuditStruct.HostAdapters += $HostAdapObj
		"<tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter IP Address</td>
		<td>$($HostAdapter.IPAddress)</td></tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter DHCP</td>
		<td>$($HostAdapter.DHCPEnabled)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter Subnet Mask</td>
		<td>$($HostAdapter.IPSubnet)</td>
		</tr></tbody>
		<tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter Gateway</td>
		<td>$($HostAdapter.DefaultIPGateway)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter MAC Address</td>
		<td>$($HostAdapter.MACAddress)</td>
		</tr></tbody>
	    <tbody><tr>
		<td>$($HostAdapter.DNSHostName)</td>
		<td>$($HostAdapter.Description)</td>
		<td>Adapter DNS Servers</td>
		<td>$($HostAdapter.DNSServerSearchOrder)</td>
		</tr></tbody>" | Out-File -Append $AuditStruct.OutputFile  
	}
	'</table><br><hr>' | out-file -Append $AuditStruct.OutputFile
	$Hklm = '2147483650'
	$Wmi = [wmiclass]"\\$($AuditStruct.Hostname)\root\default:stdRegProv"
	$RegClass = Get-WmiObject -Namespace 'Root\Default' -List -ComputerName $AuditStruct.Hostname | Where-Object { $_.Name -eq 'StdRegProv' }
	$IEKey = 'SOFTWARE\Microsoft\Internet Explorer'
	$IEVersion = ($regclass.GetStringValue($Hklm,$IEKey,'Version')).sValue
	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'Internet Explorer'
								'Method'= 'Registry Microsoft\Internet Explorer Key'
				                'Version' = $IEVersion
				                'Vendor' = 'Microsoft'
				                'InstallDate' = 'unknown'}
	$McAfeeKey='SOFTWARE\McAfee\AVEngine'
	$McAfeeDATVersion = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,'AVDATVersion')).uValue
	$McAfeeEngineVerMajor = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,'EngineVersionMajor')).uValue
	$McAfeeEngineVerMinor = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,'EngineVersionMinor')).uValue
	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'McAfee Antivirus DAT'
								'Method'= 'Registry McAfee\AVEngine Key'
				                'Version' = $McAfeeDATVersion
				                'Vendor' = 'McAfee'
				                'InstallDate' = 'unknown'
								}
	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = 'McAfee Antivirus Engine'
								'Method'= 'Registry McAfee\AVEngine Key'
				                'Version' = $McAfeeEngineVerMajor
				                'Vendor' = 'McAfee'
				                'InstallDate' = 'unknown'
								}
	$AuditStruct.InstalledSoftReg = get-installedsoftware $AuditStruct.Hostname
	foreach ($InstalledSoftware in $AuditStruct.InstalledSoftReg) {
		$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = $InstalledSoftware.Name
								'Method'= 'Registry'
				                'Version' = $InstalledSoftware.Version
				                'Vendor' = $InstalledSoftware.Publisher
				                'InstallDate' = $InstalledSoftware.InstallDate
								'Size' = $InstalledSoftware.EstimatedSize
								}
	}
	$AuditStruct.SoftwareObjs = $AuditStruct.SoftwareObjs | Sort-Object Name, Method
	'<h3>Software Information</h3>
	<table><thead><tr>
	<th>Software Name</th>
	<th>Method</th>
	<th>Version</th>
	<th>Vendor</th>
	<th>Install Date</th>
	<th>Estimated Size</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile
	foreach ($SoftwareObj in $AuditStruct.SoftwareObjs) {
		"<tbody><tr>
		<td>$($SoftwareObj.Name)</td>
		<td>$($SoftwareObj.Method)</td>
		<td>$($SoftwareObj.Version)</td>
		<td>$($SoftwareObj.Vendor)</td>
		<td>$($SoftwareObj.InstallDate)</td>
		<td>$($SoftwareObj.Size) MB</td>
		</tr></tbody>" | out-file -append $AuditStruct.OutputFile
	}
	'</table><br><hr>' | out-file -Append $AuditStruct.OutputFile
	$AuditStruct.DnsCacheObjs = Get-DNSClientCache
	'<h3>DNS Cache</h3>
	<table><thead><tr>
	<th>Name</th>
	<th>Section</th>
	<th>TTL</th>
	<th>Type</th>
	<th>Length</th>
	<th>Host Record</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile
	foreach ($DnsCacheObj in $AuditStruct.DnsCacheObjs) {
		"<tbody><tr>
		<td>$($DnsCacheObj.Name)</td>
		<td>$($DnsCacheObj.Section)</td>
		<td>$($DnsCacheObj.TTL)</td>
		<td>$($DnsCacheObj.Type)</td>
		<td>$($DnsCacheObj.Length)</td>
		<td>$($DnsCacheObj.HostRecord)</td>
		</tr></tbody>" | out-file -append $AuditStruct.OutputFile
	}
    '</table><br><hr>' | out-file -Append $AuditStruct.OutputFile
	$AuditStruct.HostEntries = Get-HostEntries

	'<h4>Hosts file</h3>
	<table><thead><tr>
	<th>IP</th>
	<th>DNS</th>
	</tr></thead>' | Out-File -Append $AuditStruct.OutputFile

	foreach ($HostEntry in $AuditStruct.HostEntries) {
		"<tbody><tr>
		<td>$($HostEntry.IP)</td>
		<td>$($HostEntry.DNS)</td>
		</tr></tbody>" | out-file -append $AuditStruct.OutputFile
	}
    '</table><br><hr>' | out-file -Append $AuditStruct.OutputFile

    $AuditStruct.EndDateTime = (Get-Date -Format 'yyyy/MM/dd HH:mm:ss')
    $AuditDuration = New-TimeSpan –Start $AuditStruct.StartDateTime –End $AuditStruct.EndDateTime
    $AuditStruct.AuditDuration = '{0:HH:mm:ss}' -f ([datetime]$AuditDuration.Ticks)   
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
								'AccessControlFalgs' = [Security.AccessControl.AceFlags]$DACL.AceFlags}
								
				$SharedNTFSACL = New-Object -TypeName PSObject -Property $Properties
	            $Objs += $SharedNTFSACL
	        }
			$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType,AccessControlFalgs -Unique
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
						'AccessControlFalgs' = 'Not Available'}
					
		$SharedNTFSACL = New-Object -TypeName PSObject -Property $Properties
	    $Objs += $SharedNTFSACL
		$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType,AccessControlFalgs -Unique
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
							$AuditStruct.PingTest = 'Succeeded'
							$i++						
		    			} 
						else {
    						$AuditStruct.PingTest = 'Failed'
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
                        throw "Critical treshold should be numeric and less than 100. Value given is $value."
                    }
                    $i++
                 }
                "^(-L|--Logstash)$" {
                    if ($value -match "^[a-zA-Z_.]+$") {
                        $InitStruct.Logstash = $value
                    } else {
                        throw "Critical treshold should be numeric and less than 100. Value given is $value."
                    }
                    $i++
                 }
          		"^(-p|--Port)$" {
                    if (($value -match "^[0-9]+$")-and ([int]$value -lt 65000)) {
                        $InitStruct.CriticalTreshold = $value
                    } else {
                        throw "Critical treshold should be numeric and less than 100. Value given is $value."
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
        Exit 3
	}	
}
Function Test-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host 'Unknown: String contains illegal characters.'
            Exit $TaskStruct.ExitCode
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

Set-ProcessPriority scripteditor BelowNormal

if($Args.count -ge 1){
	Initialize-Args $Args
}
Test-Paths
Get-WmiTrees
Start-Audit



# Write-Host $AuditJson

if ($InitStruct.Output -eq 'Html') {
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
	<td>$($AuditStruct.StartDateTime)</td>
	<td>$($AuditStruct.EndDateTime)</td>
	<td>$($AuditStruct.AuditDuration)</td>
	<td>$($AuditStruct.Executer)</td>
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
	<td>$($AuditStruct.PingTest)</td>
	</tr></tbody>
	<tbody><tr>
	<td>WMI</td>
	<td>$($AuditStruct.WmiTest)</td>
	</tr></tbody>
	<tbody><tr>
	<td>Eventlog</td>
	<td>$($AuditStruct.EventlogTest)</td>
	</tr></tbody>
	</table>
	<br><hr>
	<h3>System Information</h3>
	<table>
	<thead><tr><th>Query</th><th>Result</th></tr></thead>
	<tbody><tr><td>System Version </td><td>$($AuditStruct.HostVersion)</td></tr></tbody>
	<tbody><tr><td>System Caption </td><td>$($AuditStruct.HostCaption)</td></tr></tbody>
	<tbody><tr><td>System Service Pack </td><td>$($AuditStruct.HostServicePackMajorVersion)</td></tr></tbody>
	<tbody><tr><td>System Last Boot </td><td>$($AuditStruct.HostLastBoot)</td></tr></tbody>
	<tbody><tr><td>System Directory </td><td>$($AuditStruct.HostSystemDirectory)</td></tr></tbody>
	<tbody><tr><td>System Domain Role </td><td>$($AuditStruct.HostDomainRole)</td></tr></tbody>
	<tbody><tr><td>System Type </td><td>$($AuditStruct.HostSystemType)</td></tr></tbody>
	<tbody><tr><td>System Time Zone </td><td>$($AuditStruct.HostTimeZone)</td></tr></tbody>
	<tbody><tr><td>System Domain Controller</td><td>$($AuditStruct.HostCurrentDomainController)</td></tr></tbody>
	<tbody><tr><td>System Current Registry Size</td><td>$($AuditStruct.HostRegistryCurSize)</td></tr></tbody>
	<tbody><tr><td>System Maximum Registry Size</td><td>$($AuditStruct.HostRegistryMaxSize)</td></tr></tbody>
	<tbody><tr><td>System Manufacturer</td><td>$($AuditStruct.HostManufacturer)</td></tr></tbody>
	<tbody><tr><td>System Model</td><td>$($AuditStruct.HostModel)</td></tr></tbody>
	<tbody><tr><td>System Total Physical Memory</td><td>$($AuditStruct.HostPhysicalMemory)</td></tr></tbody>
	<tbody><tr><td>System Asset Tag</td><td>$($AuditStruct.HostAssetTag)</td></tr></tbody>
	<tbody><tr><td>System Serial Number</td><td>$($AuditStruct.HostSerialNumber)</td></tr></tbody>
	<tbody><tr><td>System Processor Name</td><td>$($AuditStruct.HostProcessorName)</td></tr></tbody>
	<tbody><tr><td>System Processor Speed</td><td>$($AuditStruct.HostProcessorSpeed)</td></tr></tbody>
	<tbody><tr><td>System Processor Voltage</td><td>$($AuditStruct.HostProcessorVoltage)</td></tr></tbody>
	<tbody><tr><td>System Processor Load Percentage</td><td>$($AuditStruct.HostProcessorLoad)</td></tr></tbody>
	</table>
	<br>	<hr>
	<h3>Disk Information</h3>
	<table><thead><tr>
	<th>Drive Name</th>
	<th>Total Size (GB)</th>
	<th>Free GB</th><th>Used GB</th>
	<th>Percentage Free</th>
	</tr></thead>" | out-file -append $InitStruct.OutputFile
	foreach ($HostLogicalDisk in $WmiStruct.Win32_LogicalDisk) {
		"<tbody><tr>
		<td>$($HostLogicalDisk.DeviceId)</td>
		<td>$($HostLogicalDisk.SizeGB) GB</td>
		<td>$($HostLogicalDisk.FreeGB) GB</td>
		<td>$($HostLogicalDisk.UsedGB) GB</td>
		<td>$($HostLogicalDisk.PerFree)</td>
		</tr></tbody>" | Out-File -Append $InitStruct.OutputFile
	}
	'</table>
	<br><hr>
	<h3>Local Group Members</h3>
	<table><thead><tr>
	<th>Group Name</th>
	<th>Group Members</tr>
	</thead>' | out-file -Append $InitStruct.OutputFile
	$InitStruct.AdminGroupMembers | foreach {
	 	$obj = new-object psobject -Property @{LocalAdmin = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)}
	 	"<tbody><tr>
		<td>$($InitStruct.ObjGroupName)</td>
		<td>$($obj.LocalAdmin)</td>
		</tr></tbody>" | out-file -Append $InitStruct.OutputFile
	} 
	'</table><br><hr>


	</html>' | out-file -append $InitStruct.OutputFile
}
if ($InitStruct.Output -eq 'Logstash') {
    $AuditJson = $AuditStruct | ConvertTo-Json
	Send-JsonOverTcp $InitStruct.Logstash $InitStruct.Port $Auditjson
}



Set-ProcessPriority scripteditor Normal

Write-Host "OK: Audit of $($AuditStruct.Hostname) succeeded in $($AuditStruct.AuditDuration) time."
exit 0