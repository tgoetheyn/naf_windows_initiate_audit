# Script name:   	naf_initiate_ms_server_audit.ps1
# Version:			1.15.02.22
# Created on:    	15/09/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Initiates audit of Microsoft server
# On Github:		https://github.com/willemdh/naf_initiate_ms_server_audit
# On OutsideIT:		http://outsideit.net/naf-initiate-ms-server-audit
# Recent History:       	
# 	16/09/2014 => Html setup + css
#	20/09/2014 => Installed software
#	21/09/2014 => DNSCache
#	22/02/2015 => Converted hash array to custom object
#	24/02/2015 => Cleanup code
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 2.0

$AuditStruct = New-Object PSObject -Property @{
    HostName = ([System.Net.Dns]::GetHostByName((hostname)).HostName).tolower();	
	HostIp = "";
	Date = (Get-Date -Format "yyyyMMdd.HHmmss");
	OutputFolder = "\\localhost\C$\Nagios\NAF\NAF_Logs\Reports";
	OutputFile = "";
	ExitCode = 3;
	LogLocal="c:\Nagios\NAF\NAF_Logs\Naf_Actions.log";
	ProcessPriority = "BelowNormal";
	HostOs = "";
	HostOsLastBoot = "";
	HostDomainRole = "";
	HostTimeZone = "";
	HostCompSystem = "";
	HostDC = "";
	HostRegistry = "";
	HostSystemEnclosure = "";
	Adapters = @();
	DnsCaches = @();
	HostCurRegSize = "";
	HostMaxRegSize = "";
	HostProcessor = "";
	HostLogicalDisks = "";
	Services = @();
	ShareObjs = @();
	ShareNtfsObjs = @();
	InstalledSoftReg = @();
	SoftwareObjs = @();
	DnsCacheObjs = @()
}

$ErrorActionPreference = "SilentlyContinue"
Write-Host "$($AuditStruct.Date) : Audit started on $($AuditStruct.hostname)"
"$($AuditStruct.Date) : Audit started on $($AuditStruct.hostname)" | Out-File -filepath $AuditStruct.LogLocal -Append

#region Functions
		
function Set-ProcessPriority { 
	param($ProcessName = $(throw "Enter process name"), $Priority = "Normal")

	Get-Process -processname $ProcessName | foreach { $_.PriorityClass = $Priority }
	# Write-Host "$($AuditStruct.Date) : Priority of process `"$($ProcessName)`" is set to `"$($Priority)`""
}

function Check-Paths { 

	$AuditStruct.OutputFile = "\\$($AuditStruct.OutputFolder)\$($AuditStruct.Hostname)`.$($AuditStruct.Date).html"
    if (!(Test-Path -path $AuditStruct.OutputFolder)) {
		New-Item -Path $AuditStruct.OutputFolder -Type directory -Force  | Out-Null
		"$($AuditStruct.Date) : Directory created on $hostname" | Out-File -filepath $AuditStruct.LogLocal -Append
	}
}

function Initiate-Audit {
	
	$AuditStruct.Date = Get-Date -format "dd/MM/yyyy HH:mm:ss"
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
	<h1>NAF - MS Server Audit</h1>
	<p>Script ran by $ENV:USERDOMAIN\$ENV:USERNAME at $($AuditStruct.Date) for <b>$($AuditStruct.Hostname)</b>
	<hr>" | out-file $AuditStruct.OutputFile
	"<h3>Connectivity Test</h3> 
	<table><thead><tr>
	<th>Test</th>
	<th>Result</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile		
	& ping -n 1 $AuditStruct.Hostname | out-null
	if($? -eq $true) {
	    "<tbody><tr>
		<td>Ping</td>
		<td>Ok</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	} 
	else {
	    "<tbody><tr>
		<td>Ping</td>
		<td>Failed</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}		
	$AuditStruct.HostOs = gwmi Win32_OperatingSystem -ComputerName $AuditStruct.Hostname
	if($? -eq $true) {
	    "<tbody><tr>
		<td>WMI</td>
		<td>Ok</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	} 
	else {
	    "<tbody><tr>
		<td>WMI</td>
		<td>Failed</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}		
	Get-EventLog System -ComputerName $AuditStruct.Hostname -Newest 1 | out-null
	if($? -eq $true) {
	    "<tbody><tr>
		<td>Eventlog</td>
		<td>Ok</td>
		</tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
	} 
	else {
	    "<tbody><tr>
		<td>Eventlog</td>
		<td>Failed</td>
		</tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
	}
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile
	$AuditStruct.HostOsLastBoot = ($AuditStruct.HostOs.ConvertToDateTime($AuditStruct.HostOs.LastBootUpTime)).ToString("yyyy-MM-dd HH:mm:ss")
	$AuditStruct.HostTimeZone = (Get-WmiObject -computername $AuditStruct.Hostname Win32_Timezone).Description
	$AuditStruct.HostCompSystem = Get-WmiObject -computername $AuditStruct.Hostname Win32_ComputerSystem
	switch ($HostDomainRole.DomainRole){
		0 { $AuditStruct.HostDomainRole = "Standalone Workstation" }
		1 { $AuditStruct.HostDomainRole = "Member Workstation" }
		2 { $AuditStruct.HostDomainRole = "Standalone Server" }
		3 { $AuditStruct.HostDomainRole = "Member Server" }
		4 { $AuditStruct.HostDomainRole = "Domain Controller" }
		5 { $AuditStruct.HostDomainRole = "Domain Controller" }
		default { $AuditStruct.HostDomainRole = "Information not available" }
	}
	$AuditStruct.HostRegistry = gwmi Win32_Registry -ComputerName $AuditStruct.Hostname
	$AuditStruct.HostSystemEnclosure = gwmi win32_systemenclosure -ComputerName $AuditStruct.Hostname
	$AuditStruct.HostProcessor = gwmi win32_processor -ComputerName $AuditStruct.Hostname
	"<h3>System Information</h3>
	<table>
	<thead><tr><th>Query</th><th>Result</th></tr></thead>
	<tbody><tr><td>System Version </td><td>$($AuditStruct.HostOs.Version)</td></tr></tbody>
	<tbody><tr><td>System Caption </td><td>$($AuditStruct.HostOs.Caption)</td></tr></tbody>
	<tbody><tr><td>System Service Pack </td><td>$($AuditStruct.HostOs.ServicePackMajorVersion)</td></tr></tbody>
	<tbody><tr><td>System Last Boot </td><td>$($AuditStruct.HostOsLastBoot)</td></tr></tbody>
	<tbody><tr><td>System Directory </td><td>$($AuditStruct.HostOs.SystemDirectory)</td></tr></tbody>
	<tbody><tr><td>System Domain Role </td><td>$($AuditStruct.HostDomainRole)</td></tr></tbody>
	<tbody><tr><td>System Time Zone </td><td>$($AuditStruct.HostTimeZone)</td></tr></tbody>
	<tbody><tr><td>System Date / Time </td><td>$($AuditStruct.Date)</td></tr></tbody>
	<tbody><tr><td>System Domain Controller</td><td>$($AuditStruct.HostDC)</td></tr></tbody>
	<tbody><tr><td>System Current Registry Size</td><td>$($AuditStruct.HostRegistry.CurrentSize)</td></tr></tbody>
	<tbody><tr><td>System Maximum Registry Size</td><td>$($AuditStruct.HostRegistry.MaximumSize)</td></tr></tbody>
	<tbody><tr><td>System Manufacturer</td><td>$($AuditStruct.HostCompSystem.Manufacturer)</td></tr></tbody>
	<tbody><tr><td>System Model</td><td>$($AuditStruct.HostCompSystem.Model)</td></tr></tbody>
	<tbody><tr><td>System Total Physical Memory</td><td>$($AuditStruct.HostCompSystem.TotalPhysicalMemory)</td></tr></tbody>
	<tbody><tr><td>System Asset Tag</td><td>$($AuditStruct.HostSystemEnclosure.SMBIOSAssetTag)</td></tr></tbody>
	<tbody><tr><td>System Serial Number</td><td>$($AuditStruct.HostSystemEnclosure.SerialNumber)</td></tr></tbody>
	<tbody><tr><td>System Processor Name</td><td>$($AuditStruct.HostProcessor.Name)</td></tr></tbody>
	<tbody><tr><td>System Processor Speed</td><td>$($AuditStruct.HostProcessor.CurrentClockSpeed)</td></tr></tbody>
	<tbody><tr><td>System Processor Voltage</td><td>$($AuditStruct.HostProcessor.CurrentVoltage)</td></tr></tbody>
	<tbody><tr><td>System Processor Load Percentage</td><td>$($AuditStruct.HostProcessor.LoadPercentage)</td></tr></tbody>
	</table><br>
	<hr>" | out-file -Append $AuditStruct.OutputFile
	$AuditStruct.HostLogicalDisks = gwmi win32_logicaldisk -ComputerName $AuditStruct.Hostname -Fi "DriveType=3" | 
		select @{Name="Computername"; Expression={$_.SystemName}}, DeviceId,
		@{Name="SizeGB";Expression={"{0:N2}" -f ($_.Size/1GB)}},
		@{Name="FreeGB";Expression={"{0:N2}" -f ($_.Freespace/1GB)}},
		@{Name="UsedGB";Expression={"{0:N2}" -f (($_.Size-$_.FreeSpace)/1GB)}},
		@{Name="PerFree";Expression={"{0:P2}" -f ($_.FreeSpace/$_.Size)}}
	"<h3>Disk Information</h3>
	<table><thead><tr>
	<th>Drive Name</th>
	<th>Total Size (GB)</th>
	<th>Free GB</th><th>Used GB</th>
	<th>Percentage Free</th>
	</tr></thead>" | out-file -Append $AuditStruct.OutputFile	
	foreach ($HostLogicalDisk in $AuditStruct.HostLogicalDisks) {
		"<tbody><tr>
		<td>$($HostLogicalDisk.DeviceId)</td>
		<td>$($HostLogicalDisk.SizeGB) GB</td>
		<td>$($HostLogicalDisk.FreeGB) GB</td>
		<td>$($HostLogicalDisk.UsedGB) GB</td>
		<td>$($HostLogicalDisk.PerFree)</td>
		</tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
	}
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile		
	$ObjSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
	$Objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
	$ObjGroupName = ($objgroup.Value).Split("\")[1]
	$AdsiGroup =[ADSI]"WinNT://$($AuditStruct.Hostname)/$objgroupname" 
	$AdminGroupMembers = @($AdsiGroup.psbase.Invoke("Members"))
	"<h3>Local Group Members</h3>
	<table><thead><tr>
	<th>Group Name</th>
	<th>Group Members</tr>
	</thead>" | out-file -Append $AuditStruct.OutputFile
	$AdminGroupMembers | foreach {
	 	$obj = new-object psobject -Property @{LocalAdmin = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
	 	"<tbody><tr>
		<td>$ObjGroupName</td>
		<td>$($obj.LocalAdmin)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	} 
	"</table><br><hr>" | out-file -Append $AuditStruct.OutputFile
	"<h3>Service Configuration</h3>
	<table><thead><tr>
	<th>Service Name</th>
	<th>Display Name</th><th>Status</th>
	<th>Startup Type</th>
	</tr></thead>" | out-file -Append $AuditStruct.OutputFile
	$AuditStruct.Services = Get-Service -ComputerName $AuditStruct.Hostname
	foreach ($service in $AuditStruct.Services) {
		$StartupType = Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$($service.Name)'"
	    "<tbody><tr><td>$($service.Name)</td>
		<td>$($service.DisplayName)</td>
		<td>$($service.Status)</td>
		<td>$($StartupType.StartMode)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile		   
	}
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile

	"<h3>Share Permissions</h3>
	<table><thead><tr><th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile

	$AuditStruct.ShareObjs = GetSharedFolderPermission $AuditStruct.Hostname
	foreach ($ShareObj in $AuditStruct.ShareObjs){
		"<tbody><tr>
		<td>$($ShareObj.SharedFolderName)</td>
		<td>$($ShareObj.SecurityPrincipal)</td>
		<td>$($ShareObj.FileSystemRights)</td>
		<td>$($ShareObj.AccessControlType)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile
	"<h3>Share NTFS Permissions</h3>
	<table><thead><tr>
	<th>Sharename</th>
	<th>Security Principal</th>
	<th>File System Rights</th>
	<th>Access Control Type</th>
	<th>Access Control Flags</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile
	$AuditStruct.ShareNtfsObjs = GetSharedFolderNTFSPermission $AuditStruct.Hostname
	foreach ($ShareNtfsObj in $AuditStruct.ShareNtfsObjs){
		"<tbody><tr>
		<td>$($ShareNtfsObj.SharedFolderName)</td>
		<td>$($ShareNtfsObj.SecurityPrincipal)</td>
		<td>$($ShareNtfsObj.FileSystemRights)</td>
		<td>$($ShareNtfsObj.AccessControlType)</td>
		<td>$($ShareNtfsObj.AccessControlFalgs)</td>
		</tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	}
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile
	"<h3>Network Adapters</h3>
	<table><thead><tr>
	<th>Hostname</th>
	<th>Adapter Name</th>
	<th>Adapter Query</th>
	<th>Adapter Query Result</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile
	$AuditStruct.Adapters = gwmi win32_networkadapterconfiguration -computername $AuditStruct.Hostname -Filter 'ipenabled = "true"'
	foreach ($HostAdapter in $AuditStruct.Adapters) {
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
	"</table><br><hr>" | out-file -Append $AuditStruct.OutputFile
	$Hklm = "2147483650"
	$Wmi = [wmiclass]"\\$($AuditStruct.Hostname)\root\default:stdRegProv"
	$RegClass = gwmi -Namespace "Root\Default" -List -ComputerName $AuditStruct.Hostname | Where-Object { $_.Name -eq "StdRegProv" }
	$IEKey = "SOFTWARE\Microsoft\Internet Explorer"
	$IEVersion = ($regclass.GetStringValue($Hklm,$IEKey,"Version")).sValue

	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = "Internet Explorer"
								'Method'= "Registry Microsoft\Internet Explorer Key"
				                'Version' = $IEVersion
				                'Vendor' = "Microsoft"
				                'InstallDate' = "unknown"
								}
	$McAfeeKey="SOFTWARE\McAfee\AVEngine"
	$McAfeeDATVersion = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,"AVDATVersion")).uValue
	$McAfeeEngineVerMajor = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,"EngineVersionMajor")).uValue
	$McAfeeEngineVerMinor = ($RegClass.GetDWORDValue($Hklm,$McAfeeKey,"EngineVersionMinor")).uValue
	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = "McAfee Antivirus DAT"
								'Method'= "Registry McAfee\AVEngine Key"
				                'Version' = $McAfeeDATVersion
				                'Vendor' = "McAfee"
				                'InstallDate' = "unknown"
								}
	$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = "McAfee Antivirus Engine"
								'Method'= "Registry McAfee\AVEngine Key"
				                'Version' = $McAfeeEngineVerMajor
				                'Vendor' = "McAfee"
				                'InstallDate' = "unknown"
								}
	$AuditStruct.InstalledSoftReg = get-installedsoftware $AuditStruct.Hostname
	foreach ($InstalledSoftware in $AuditStruct.InstalledSoftReg) {
		$AuditStruct.SoftwareObjs += New-Object -TypeName PSCustomObject -Property @{
					            'Name' = $InstalledSoftware.Name
								'Method'= "Registry"
				                'Version' = $InstalledSoftware.Version
				                'Vendor' = $InstalledSoftware.Publisher
				                'InstallDate' = $InstalledSoftware.InstallDate
								'Size' = $InstalledSoftware.EstimatedSize
								}
	}
	$AuditStruct.SoftwareObjs = $AuditStruct.SoftwareObjs | sort Name, Method
	"<h3>Software Information</h3>
	<table><thead><tr>
	<th>Software Name</th>
	<th>Method</th>
	<th>Version</th>
	<th>Vendor</th>
	<th>Install Date</th>
	<th>Estimated Size</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile
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
	"</table><br><hr>" | out-file -Append $AuditStruct.OutputFile
	$AuditStruct.DnsCacheObjs = Get-DNSClientCache
	"<h3>DNS Cache</h3>
	<table><thead><tr>
	<th>Name</th>
	<th>Section</th>
	<th>TTL</th>
	<th>Type</th>
	<th>Length</th>
	<th>Host Record</th>
	</tr></thead>" | Out-File -Append $AuditStruct.OutputFile
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
	"</table><br><hr>" | out-file -Append $AuditStruct.OutputFile


	"</html>" | Out-File -Append $AuditStruct.OutputFile
}

Function GetSharedFolderPermission($ComputerName){
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
								'ConnectionStatus' = "Success"
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
						'ConnectionStatus' = "Fail"
						'SharedFolderName' = "Not Available"
						'SecurityPrincipal' = "Not Available"
						'FileSystemRights' = "Not Available"
						'AccessControlType' = "Not Available"}
		$SharedACLs = New-Object -TypeName PSObject -Property $Properties
		$Objs += $SharedACLs
		$Objs|Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights,AccessControlType
	}
}

Function GetSharedFolderNTFSPermission($ComputerName){
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
								'ConnectionStatus' = "Success"
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
						'ConnectionStatus' = "Fail"
						'SharedFolderName' = "Not Available"
						'SecurityPrincipal' = "Not Available"
						'FileSystemRights' = "Not Available"
						'AccessControlType' = "Not Available"
						'AccessControlFalgs' = "Not Available"}
					
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
            $UninstallKeys = $Registry.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Uninstall",$False); 
            $UninstallKeys.GetSubKeyNames()|%{ 
                $SubKey = $UninstallKeys.OpenSubKey($_,$False); 
                $DisplayName = $SubKey.GetValue("DisplayName"); 
                If ($DisplayName.Length -gt 0){ 
                    $Entry = $Base | Select-Object * 
                    $Entry.ComputerName = $ComputerName; 
                    $Entry.Name = $DisplayName.Trim();  
                    $Entry.Publisher = $SubKey.GetValue("Publisher");  
                    [ref]$ParsedInstallDate = Get-Date                     
                    $Entry.InstallDate = $SubKey.GetValue("InstallDate") 	                    
                    $Entry.EstimatedSize = [Math]::Round($SubKey.GetValue("EstimatedSize")/1KB,1); 
                    $Entry.Version = $SubKey.GetValue("DisplayVersion"); 
                    [Void]$Results.Add($Entry); 
                } 
            } 
             
                If ([IntPtr]::Size -eq 8){ 
                $UninstallKeysWow6432Node = $Null; 
                $SubKeyWow6432Node = $Null; 
                $UninstallKeysWow6432Node = $Registry.OpenSubKey("Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",$False); 
                    If ($UninstallKeysWow6432Node) { 
                        $UninstallKeysWow6432Node.GetSubKeyNames()|%{ 
                        $SubKeyWow6432Node = $UninstallKeysWow6432Node.OpenSubKey($_,$False); 
                        $DisplayName = $SubKeyWow6432Node.GetValue("DisplayName"); 
                        If ($DisplayName.Length -gt 0){ 
                            $Entry = $Base | Select-Object * 
                            $Entry.ComputerName = $ComputerName; 
                            $Entry.Name = $DisplayName.Trim();  
                            $Entry.Publisher = $SubKeyWow6432Node.GetValue("Publisher");  
                            [ref]$ParsedInstallDate = Get-Date                      
                            $Entry.InstallDate = $SubKeyWow6432Node.GetValue("InstallDate")                         
                            $Entry.EstimatedSize = [Math]::Round($SubKeyWow6432Node.GetValue("EstimatedSize")/1KB,1); 
                            $Entry.Version = $SubKeyWow6432Node.GetValue("DisplayVersion"); 
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
	Invoke-Expression "IPConfig /DisplayDNS" | 
	Select-String -Pattern "Record Name" -Context 0,5 | 
	    %{ 
	        $Record = New-Object PSObject -Property @{ 
	        Name=($_.Line -Split ":")[1] 
	        Type=($_.Context.PostContext[0] -Split ":")[1] 
	        TTL=($_.Context.PostContext[1] -Split ":")[1] 
	        Length=($_.Context.PostContext[2] -Split ":")[1] 
	        Section=($_.Context.PostContext[3] -Split ":")[1] 
	        HostRecord=($_.Context.PostContext[4] -Split ":")[1] 
	        } 
	        $DNSCache +=$Record 
	    } 
	    return $DNSCache 
}

Function Process-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args,
        [Parameter(Mandatory=$True)]$Return
    )

    For ( $i = 0; $i -lt $Args.count-1; $i++ ) {     
        $CurrentArg = $Args[$i].ToString()
        $Value = $Args[$i+1]
        If (($CurrentArg -cmatch "-H") -or ($CurrentArg -match "--Hostname")) {
            If (Check-Strings $Value) {
                $Return.Hostname = $Value  
				$Return.KnownArgCount+=1
            }
        }	
        ElseIf (($CurrentArg -cmatch "-h")-or ($CurrentArg -match "--help")) { 
			$Return.KnownArgCount+=1
			Write-Help
			Exit $Return.ExitCode
		}				
       	else {
			$Return.UnkArgCount+=1
		}
    }		
	$ArgHelp = $Args[0].ToString()	
	if (($ArgHelp -match "--help") -or ($ArgHelp -cmatch "-h") ) {
		Write-Help 
		Exit $Return.ExitCode
	}	
	if ($Return.UnkArgCount -ge $Return.KnownArgCount) {
		Write-Host "Unknown: Illegal arguments detected!"
        Exit $Return.ExitCode
	}
	if ($Return.Hostname -eq $DefaultString) {
		$Return.Hostname = ([System.Net.Dns]::GetHostByName((hostname)).HostName).tolower()
	}
    Return $Return
}

Function Check-Strings {
    Param ( [Parameter(Mandatory=$True)][string]$String )
    # `, `n, |, ; are bad, I think we can leave {}, @, and $ at this point.
    $BadChars=@("``", "|", ";", "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host "Unknown: String contains illegal characters."
            Exit $NetStruct.ExitCode
        }
    }
    Return $true
} 

Function Write-Help {
    Write-Host "naf_initiate_ms_server_audit.ps1:`n`tThis script is designed to audit a MS server and output result to html."
    Write-Host "Arguments:"
    Write-Host "`t-H or --Hostname => Required hostname of system, default is localhost."
    Write-Host "`t-w or --Warning => Not yet implemented."
    Write-Host "`t-c or --Critial => Not yet implemented."
    Write-Host "`t-h or --Help => Print this help output."
} 

#endregion Functions

# Main

Set-ProcessPriority scripteditor BelowNormal

if($Args.count -ge 1){
	$AuditStruct = Process-Args $Args $AuditStruct
}

Check-Paths
Initiate-Audit

Set-ProcessPriority scripteditor Normal