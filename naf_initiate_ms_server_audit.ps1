# Script name:   	naf_initiate_ms_server_audit.ps1
# Version:			0.14.09.17
# Created on:    	15/09/2014																			
# Author:        	D'Haese Willem
# Purpose:       	Initiates audit of Microsoft server
# On Github:		https://github.com/willemdh/naf_initiate_ms_server_audit
# To do:			Everything
# History:       	
#	15/09/2014 => Initial setup
# 	16/09/2014 => Html setup + css
#	17/09/2014 => Adding more information
# How to:
#	1) Put the script in the NSCP scripts folder
#	2) In the nsclient.ini configuration file, define the script like this:
#		naf_initiate_ms_server_audit=cmd /c echo scripts\naf_initiate_ms_server_audit.ps1 $ARG1$; exit $LastExitCode | powershell.exe -command -
#	3) Make a command in Nagios like this:
#		naf_initiate_ms_server_audit => $USER1$/check_nrpe -H $HOSTADDRESS$ -p 5666 -t 60 -c naf_initiate_ms_server_audit -a $ARG1$
#	4) Configure your service in Nagios:
#		- Make use of the above created command
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the
# 	GNU General Public License as published by the Free Software Foundation, either version 3 of 
#   the License, or (at your option) any later version.
#   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
#	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
# 	See the GNU General Public License for more details.You should have received a copy of the GNU
#   General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

#Requires –Version 2.0

[String]$DefaultString = "ABCD123"
[Int]$DefaultInt = -99

$AuditStruct = @{}
	[string]$AuditStruct.Hostname = $DefaultString
	[string]$AuditStruct.HostIp = $DefaultString
	[string]$AuditStruct.OutputFile = $DefaultString
	[string]$AuditStruct.HostOs = $DefaultString
	[string]$AuditStruct.HostOsVersion = $DefaultString
	[string]$AuditStruct.HostOsCaption = $DefaultString
	[string]$AuditStruct.HostOsSp = $DefaultString
	[string]$AuditStruct.HostOsLastBoot = $DefaultString
	[string]$AuditStruct.HostOsSysDir = $DefaultString
	[string]$AuditStruct.HostDomainRole = $DefaultString
	[string]$AuditStruct.HostTimeZone = $DefaultString
	[string]$AuditStruct.HostDateTime = $DefaultString
	[string]$AuditStruct.HostDC = $DefaultString
	[Int]$AuditStruct.HostCurRegSize = $DefaultInt
	[Int]$AuditStruct.HostMaxRegSize = $DefaultInt
	[int]$AuditStruct.ExitCode = 3
	[int]$AuditStruct.UnkArgCount = 0
	[int]$AuditStruct.KnownArgCount = 0
	[Int]$AuditStruct.WarnHigh = $DefaultInt
    [Int]$AuditStruct.CritHigh = $DefaultInt
    [Int]$AuditStruct.WarnLow = $DefaultInt


$ErrorActionPreference = "silentlycontinue"

#region Functions

function Initiate-Audit{
	param(
		[Parameter(Mandatory=$True)]$AuditStruct
	)

	$Date = Get-Date -Format "yyyyMMdd.HHmmss"

#	$remoteserver = ([System.Net.Dns]::GetHostByName((hostname)).HostName).tolower()
	$AuditStruct.OutputFile = "\\$($AuditStruct.Hostname)\C$\Nagios\$($AuditStruct.Hostname)`.$Date.html"

	$HeaderDate = $Date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	$HtmlHeader = "
<!DOCTYPE html>
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
<h1>Nagios XI Automatisation Framework MS Server Audit</h1>
<p>Script by $ENV:USERDOMAIN\$ENV:USERNAME at $HeaderDate for <b>$($AuditStruct.Hostname)</b>
<hr>"
	$HtmlHeader | out-file $AuditStruct.OutputFile

	"<h3>Connectivity Test</h3>" | out-file -Append $AuditStruct.OutputFile
	"<table><thead><tr><th>Test</th><th>Result</th></tr></thead>" | Out-File -Append $AuditStruct.OutputFile
	& ping -n 1 $AuditStruct.Hostname | out-null
	if($? -eq $true) {
	    "<tbody><tr><td>Ping</td><td>Ok</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	    } 
	else {
	    "<tbody><tr><td>Ping</td><td>Failed</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	    }
	gwmi Win32_OperatingSystem -ComputerName $AuditStruct.Hostname | out-null
	if($? -eq $true) {
	    "<tbody><tr><td>WMI</td><td>Ok</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	    } 
	else {
	    "<tbody><tr><td>WMI</td><td>Failed</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
	    continue
	    }
	Get-EventLog System -ComputerName $AuditStruct.Hostname -Newest 1 | out-null
	if($? -eq $true) {
	    "<tbody><tr><td>Eventlog</td><td>Ok</td></tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
	    } 
	else {
	    "<tbody><tr><td>Eventlog</td><td>Failed</td></tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
	    }
	"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile


# Section one, OS
$AuditStruct.HostOs = Get-WmiObject win32_operatingsystem -ComputerName $AuditStruct.Hostname
$AuditStruct.HostOsVersion = $AuditStruct.HostOs.Version
$AuditStruct.HostOsCaption = $AuditStruct.HostOs.Caption
$AuditStruct.HostOsSp = $AuditStruct.HostOs.ServicePackMajorVersion
$AuditStruct.HostOsLastBoot = $AuditStruct.HostOs.ConvertToDateTime($AuditStruct.HostOs.LastBootUpTime)
$AuditStruct.HostOsLastBoot = ($AuditStruct.HostOsLastBoot).ToString("yyyy-MM-dd HH:mm:ss")
$AuditStruct.HostOsSysDir = $AuditStruct.HostOs.SystemDirectory
$TimeZone = Get-WmiObject -computername $AuditStruct.Hostname Win32_Timezone
$AuditStruct.HostTimeZone = $TimeZone.Description
$HostDomainRole = Get-WmiObject -computername $AuditStruct.Hostname Win32_ComputerSystem
switch ($HostDomainRole.DomainRole){
	0 { $AuditStruct.HostDomainRole = "Standalone Workstation" }
	1 { $AuditStruct.HostDomainRole = "Member Workstation" }
	2 { $AuditStruct.HostDomainRole = "Standalone Server" }
	3 { $AuditStruct.HostDomainRole = "Member Server" }
	4 { $AuditStruct.HostDomainRole = "Domain Controller" }
	5 { $AuditStruct.HostDomainRole = "Domain Controller" }
	default { $AuditStruct.HostDomainRole = "Information not available" }
}
$AuditStruct.HostDateTime = $AuditStruct.HostOs.ConvertToDateTime($AuditStruct.HostOs.LocalDateTime)
$AuditStruct.HostDateTime = ($AuditStruct.HostDateTime).ToString("yyyy-MM-dd HH:mm:ss")
$AuditStruct.HostDC = Get-ADDomainController | Select -exp HostName
$DCDateTime = Get-WmiObject win32_operatingsystem -ComputerName $AuditStruct.HostDC
$DCDateTime = $DCDateTime.ConvertToDateTime($DCDateTime.LocalDateTime)
$DCDateTime = $DCDateTime.ToString("yyyy-MM-dd HH:mm:ss")
[Int]$AuditStruct.HostCurRegSize = $DefaultInt
[Int]$AuditStruct.HostMaxRegSize = $DefaultInt
$AuditStruct.HostCurRegSize = (gwmi Win32_Registry -ComputerName $AuditStruct.Hostname).CurrentSize
$AuditStruct.HostMaxRegSize = (gwmi Win32_Registry -ComputerName $AuditStruct.Hostname).MaximumSize
$HostManuf = (gwmi win32_computersystem -ComputerName $AuditStruct.Hostname).Manufacturer
$HostModel = (gwmi win32_computersystem -ComputerName $AuditStruct.Hostname).Model
$HostTotalRam = (gwmi win32_computersystem -ComputerName $AuditStruct.Hostname).TotalPhysicalMemory
$HostAssetTag = (gwmi win32_systemenclosure -ComputerName $AuditStruct.Hostname).SMBIOSAssetTag
$HostSerialNum = (gwmi win32_systemenclosure -ComputerName $AuditStruct.Hostname).SerialNumber
$HostProcName = (gwmi win32_processor -ComputerName $AuditStruct.Hostname).Name
$HostProcSpeed = (gwmi win32_processor -ComputerName $AuditStruct.Hostname).CurrentClockSpeed
$HostProcVoltage = (gwmi win32_processor -ComputerName $AuditStruct.Hostname).CurrentVoltage
$HostProcLoad = (gwmi win32_processor -ComputerName $AuditStruct.Hostname).LoadPercentage

$HtmlOs = "
<h3>System Information</h3>
<table>
<thead><tr><th>Query</th><th>Result</th></tr></thead>
<tbody><tr><td>System Version </td><td>$($AuditStruct.HostOsVersion)</td></tr></tbody>
<tbody><tr><td>System Caption </td><td>$($AuditStruct.HostOsCaption)</td></tr></tbody>
<tbody><tr><td>System Service Pack </td><td>$($AuditStruct.HostOsSp)</td></tr></tbody>
<tbody><tr><td>System Last Boot </td><td>$($AuditStruct.HostOsLastBoot)</td></tr></tbody>
<tbody><tr><td>System Directory </td><td>$($AuditStruct.HostOsSysDir)</td></tr></tbody>
<tbody><tr><td>System Domain Role </td><td>$($AuditStruct.HostDomainRole)</td></tr></tbody>
<tbody><tr><td>System Time Zone </td><td>$($AuditStruct.HostTimeZone)</td></tr></tbody>
<tbody><tr><td>System Date / Time </td><td>$($AuditStruct.HostDateTime)</td></tr></tbody>
<tbody><tr><td>System Domain Controller</td><td>$($AuditStruct.HostDC)</td></tr></tbody>
<tbody><tr><td>DC Date / Time</td><td>$DCDateTime</td></tr></tbody>
<tbody><tr><td>System Current Registry Size</td><td>$($AuditStruct.HostCurRegSize)</td></tr></tbody>
<tbody><tr><td>System Maximum Registry Size</td><td>$($AuditStruct.HostMaxRegSize)</td></tr></tbody>
<tbody><tr><td>System Manufacturer / Time</td><td>$HostManuf</td></tr></tbody>
<tbody><tr><td>System Model</td><td>$HostModel</td></tr></tbody>
<tbody><tr><td>System Total Physical Memory</td><td>$HostTotalRam</td></tr></tbody>
<tbody><tr><td>System Asset Tag</td><td>$HostAssetTag</td></tr></tbody>
<tbody><tr><td>System Serial Number</td><td>$HostSerialNum</td></tr></tbody>
<tbody><tr><td>System Processor Name</td><td>$HostProcName</td></tr></tbody>
<tbody><tr><td>System Processor Speed</td><td>$HostProcSpeed</td></tr></tbody>
<tbody><tr><td>System Processor Voltage</td><td>$HostProcVoltage</td></tr></tbody>
<tbody><tr><td>System Processor Load Percentage</td><td>$HostProcLoad</td></tr></tbody>
</table><br>
<hr>
"
$HtmlOs | out-file -Append $AuditStruct.OutputFile

$HostDrives = gwmi win32_logicaldisk -ComputerName $AuditStruct.Hostname -Fi "DriveType=3" | 
	select @{Name="Computername"; Expression={$_.SystemName}}, DeviceId,
	@{Name="SizeGB";Expression={"{0:N2}" -f ($_.Size/1GB)}},
	@{Name="FreeGB";Expression={"{0:N2}" -f ($_.Freespace/1GB)}},
	@{Name="UsedGB";Expression={"{0:N2}" -f (($_.Size-$_.FreeSpace)/1GB)}},
	@{Name="PerFree";Expression={"{0:P2}" -f ($_.FreeSpace/$_.Size)}}

$HtmlDrives = "
<h3>Disk Information</h3>
<table><thead><tr><th>Drive Name</th><th>Total Size (GB)</th><th>Free GB</th><th>Used GB</th><th>Percentage Free</th></tr></thead>
"
$HtmlDrives | out-file -Append $AuditStruct.OutputFile	
	
foreach ($HostDrive in $HostDrives) {
	"<tbody><tr><td>$($HostDrive.DeviceId)</td><td>$($HostDrive.SizeGB)</td><td>$($HostDrive.FreeGB)</td><td>$($HostDrive.UsedGB)</td><td>$($HostDrive.PerFree)</td></tr></tbody>" | Out-File -Append $AuditStruct.OutputFile
}
"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile

$objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
$ObjGroupName = ($objgroup.Value).Split("\")[1]
$group =[ADSI]"WinNT://$($AuditStruct.Hostname)/$objgroupname" 
$members = @($group.psbase.Invoke("Members"))

$HtmlAdmins = "
<h3>Local Group Members</h3>
<table><thead><tr><th>Group Name</th><th>Group Members</tr></thead>
"
$HtmlAdmins | out-file -Append $AuditStruct.OutputFile

$members | foreach {
 $obj = new-object psobject -Property @{
 LocalAdmin = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
 }
 "<tbody><tr><td>$ObjGroupName</td><td>$($obj.LocalAdmin)</td><tr></tbody>" | out-file -Append $AuditStruct.OutputFile
 } 
 "</table><br><hr>" | out-file -Append $AuditStruct.OutputFile
 
$HtmlServices = "
<h3>Service Configuration</h3>
<table><thead><tr><th>Service Name</th><th>Display Name</th><th>Status</th><th>Startup Type</th></tr></thead>
"
$HtmlServices | out-file -Append $AuditStruct.OutputFile
$Services = Get-Service -ComputerName $AuditStruct.Hostname
foreach ($service in $services) {
	$StartupType = Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='$($service.Name)'"
    "<tbody><tr><td>$($service.Name)</td><td>$($service.DisplayName)</td><td>$($service.Status)</td><td>$($StartupType.StartMode)</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
   
}
"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile

$HtmlShares = "
<h3>Share Permissions</h3>
<table><thead><tr><th>Sharename</th><th>Security Principal</th><th>File System Rights</th><th>Access Control Type</th></tr></thead>
"
$HtmlShares | Out-File -Append $AuditStruct.OutputFile

$ShareObjs = GetSharedFolderPermission $AuditStruct.Hostname
foreach ($ShareObj in $ShareObjs){
	"<tbody><tr><td>$($ShareObj.SharedFolderName)</td><td>$($ShareObj.SecurityPrincipal)</td><td>$($ShareObj.FileSystemRights)</td><td>$($ShareObj.AccessControlType)</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
}
"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile

$HtmlShareNtfs = "
<h3>Share NTFS Permissions</h3>
<table><thead><tr><th>Sharename</th><th>Security Principal</th><th>File System Rights</th><th>Access Control Type</th><th>Access Control Flags</th></tr></thead>
"
$HtmlShareNtfs | Out-File -Append $AuditStruct.OutputFile

$ShareNtfsObjs = GetSharedFolderNTFSPermission $AuditStruct.Hostname
foreach ($ShareNtfsObj in $ShareNtfsObjs){
	"<tbody><tr><td>$($ShareNtfsObj.SharedFolderName)</td><td>$($ShareNtfsObj.SecurityPrincipal)</td><td>$($ShareNtfsObj.FileSystemRights)</td><td>$($ShareNtfsObj.AccessControlType)</td><td>$($ShareNtfsObj.AccessControlFalgs)</td></tr></tbody>" | out-file -Append $AuditStruct.OutputFile
}
"</table><br><hr>" | Out-File -Append $AuditStruct.OutputFile


"</html>" | Out-File -Append $AuditStruct.OutputFile
}

Function GetSharedFolderPermission($ComputerName)
{
	#test server connectivity
	$PingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
	if($PingResult)
	{
		#check the credential whether trigger
		if($Credential)
		{
			$SharedFolderSecs = Get-WmiObject -Class Win32_LogicalShareSecuritySetting `
			-ComputerName $ComputerName -Credential $Credential -ErrorAction SilentlyContinue
		}
		else
		{
			$SharedFolderSecs = Get-WmiObject -Class Win32_LogicalShareSecuritySetting `
			-ComputerName $ComputerName -ErrorAction SilentlyContinue
		}
		
		foreach ($SharedFolderSec in $SharedFolderSecs) 
		{ 
		    $Objs = @() #define the empty array
			
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
				
				#customize the property
				$Properties = @{'ComputerName' = $ComputerName
								'ConnectionStatus' = "Success"
								'SharedFolderName' = $SharedFolderSec.Name
								'SecurityPrincipal' = $UserName
								'FileSystemRights' = [Security.AccessControl.FileSystemRights]`
								$($DACL.AccessMask -as [Security.AccessControl.FileSystemRights])
								'AccessControlType' = [Security.AccessControl.AceType]$DACL.AceType}
				$SharedACLs = New-Object -TypeName PSObject -Property $Properties
				$Objs += $SharedACLs

	        }
			$Objs|Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal, `
			FileSystemRights,AccessControlType
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
		$Objs|Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal, `
		FileSystemRights,AccessControlType
	}
}

Function GetSharedFolderNTFSPermission($ComputerName)
{
	#test server connectivity
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
								'FileSystemRights' = [Security.AccessControl.FileSystemRights]`
								$($DACL.AccessMask -as [Security.AccessControl.FileSystemRights])
								'AccessControlType' = [Security.AccessControl.AceType]$DACL.AceType
								'AccessControlFalgs' = [Security.AccessControl.AceFlags]$DACL.AceFlags}
								
				$SharedNTFSACL = New-Object -TypeName PSObject -Property $Properties
	            $Objs += $SharedNTFSACL
	        }
			$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights, `
			AccessControlType,AccessControlFalgs -Unique
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
		$Objs |Select-Object ComputerName,ConnectionStatus,SharedFolderName,SecurityPrincipal,FileSystemRights, `
		AccessControlType,AccessControlFalgs -Unique
	}
} 

function get-shareacl {
	Param ( 
        [Parameter(Mandatory=$True)]$Share,
		[Parameter(Mandatory=$True)]$Server
     )
	 
    #$shares = gwmi -Class win32_share -ComputerName $remoteserver | select -ExpandProperty Name  
    $Acl = $null  
    $ObjShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $Server
    try {  
        $SD = $ObjShareSec.GetSecurityDescriptor().Descriptor    
        foreach($ace in $SD.DACL){   
            $UserName = $ace.Trustee.Name      
            If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}    
            If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString }      
            [Array]$Acl += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType)  
            }            
    }   
    catch {  }
    $Acl
}

Function Process-Args {
    Param ( 
        [Parameter(Mandatory=$True)]$Args,
        [Parameter(Mandatory=$True)]$Return
    )
	
# Loop through all passed arguments

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

# Function to check strings for invalid and potentially malicious chars

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
    Write-Host "`t-w or --Warning => Warning threshold for number connections, not yet implemented."
    Write-Host "`t-c or --Critial => Critical threshold for number of connections, not yet implemented."
    Write-Host "`t-h or --Help => Print this help output."
} 

#endregion Functions

# Main
if($Args.count -ge 1){
	$AuditStruct = Process-Args $Args $AuditStruct
}
if ($AuditStruct.Hostname -eq $DefaultString) {
	$AuditStruct.Hostname = ([System.Net.Dns]::GetHostByName((hostname)).HostName).tolower()
}

Initiate-Audit -AuditStruct $AuditStruct