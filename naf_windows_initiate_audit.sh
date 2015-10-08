#!/bin/bash

# Script Name:      naf_windows_initiate_audit.sh
# Version:          v1.08.151008
# Created On:       15/09/2014
# Author:           Willem D'Haese
# Purpose:          Initiates audit of a Windows host and output to Html or Logstash.
# On Github:        https://github.com/willemdh/naf_windows_initiate_audit
# On OutsideIT:     http://outsideit.net/naf-windows-initiate-audit
# Recent History:
#       15/09/14 => Inital configuration
#       21/09/14 => Updated code and documentation
#       24/02/15 => Cleanup and compatibility with NAF / Reactor
#       07/10/15 => Inserted writelog and test audit result exitcode
#       08/10/15 => Merge with hostgroup target code
# Copyright:
#       This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#       by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed
#       in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#       PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public
#       License along with this program.  If not, see <http://www.gnu.org/licenses/>.

TEMP=`getopt -o G:T:O:U:L:P:N:p: --long Gateway:,Target:,Output:,LogstashServer:,LogstashServerPort:,NagiosServer:,NagiosUser:,NagiosPassword: -n 'naf_windows_initiate_audit.sh' -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$TEMP"
while true ; do
    case "$1" in
        -G|--Gateway)               Gateway=$2 ; shift 2 ;;
        -T|--Target)                Target=$2 ; shift 2 ;;
        -N|--NagiosServer)          NagiosServer=$2 ; shift 2 ;;
        -U|--NagiosUser)            NagiosUser=$2 ; shift 2 ;;
        -P|--NagiosPassword)        NagiosPassword=$2 ; shift 2 ;;
        -O|--Output)                Output=$2 ; shift 2 ;;
        -L|--LogstashServer)        LogstashServer=$2 ; shift 2 ;;
        -p|--LogstashPort)          LogstashPort=$2 ; shift 2 ;;
        --)                         shift ; break ;;
        *)                          echo "Argument parsing issue: $1" ; exit 1 ;;
    esac
done

Logfile=/var/log/naf_actions.log
Verbose=1

writelog () {
  if [ -z "$1" ] ; then echo "WriteLog: Log parameter #1 is zero length. Please debug..." ; exit 1
  else
    if [ -z "$2" ] ; then echo "WriteLog: Severity parameter #2 is zero length. Please debug..." ; exit 1
    else
      if [ -z "$3" ] ; then echo "WriteLog: Message parameter #3 is zero length. Please debug..." ; exit 1 ; fi
    fi
  fi
  Now=$(date '+%Y-%m-%d %H:%M:%S,%3N')
  if [ $1 = "Verbose" -a $Verbose = 1 ] ; then echo "$Now: $2: $3"
  elif [ $1 = "Verbose" -a $Verbose = 0 ] ; then :
  elif [ $1 = "Output" ] ; then echo "${Now}: $2: $3"
  elif [ -f $1 ] ; then echo "${Now}: $2: $3" >> $1
  fi
}

writelog Verbose Info "Audit initiated on target $Target."
writelog Output Info "Audit initiated on target $Target."
writelog Verbose Info "Argumentlist: Gateway: ${Gateway}. Target: ${Target}. NagiosServer: ${NagiosServer}. NagiosUser: ${nagiosUser}. NagiosPassword: ${nagiosPassword}. Output: ${Output}. LogstashServer: ${LogstashServer}. LogstashPort: ${LogstashPort}."

#NagiosLogServer="srvnaglog01"
#NagiosLogServerPort=5600
#NagiosXiServer="srvnagios01"
#NagReadOnlyUser="sys_naf"
#NagReadOnlyPw="Gent1234"

IsHostgroup=false
IsHost=false
OutputSuccess=0
OutputFailed=0
OutputUnknown=0

writelog Verbose Info "Checking if $Target is a hostgroup on ${NagiosServer}."
HostgroupList=$(curl -s $NagiosUser:$NagiosPassword@$NagiosServer/nagios/cgi-bin/objectjson.cgi?query=hostgrouplist)
if (echo $HostgroupList | grep -w "\"$Target\"" > /dev/null) ; then
    IsHostgroup=true
    writelog Verbose Info "$Target is a hostgroup."
else
    IsHostgroup=false
    writelog Verbose Info "$Target is not a hostgroup."
fi
writelog Verbose Info "Checking if $Target is a host on ${NagiosServer}."
HostList=$(curl -s $NagiosUser:$NagiosPassword@$NagiosServer/nagios/cgi-bin/objectjson.cgi?query=hostlist)
if (echo $HostList | grep -w "\"$Target\"" > /dev/null) ; then
    IsHost=true
    writelog Verbose Info "$Target is a host."
else
    IsHost=false
    writelog Verbose Info "$Target is not a host."
fi

if [[ $IsHost == true ]] && [[ $IsHostgroup == true ]] ; then
    writelog output Error "Target $Target exist as a host and as a hostgroup. Exiting..."
    exit 1
elif [[ $IsHost == false ]] && [[ $IsHostgroup == false ]] ; then
    writelog output Error "Target $Target does not exist as a host or a hostgroup. Exiting..."
    exit 1
elif [[ $IsHost == true ]]; then
    writelog Verbose Info "Audit script started with output $Output on host ${Target}."
    writelog Output Info "Audit script started with output $Output on host ${Target}."
    if [[ $Output == "Html" ]]; then
        Arg="-H \"$Target\" -O \"$Output\""
        /usr/local/nagios/libexec/check_nrpe -H $Gateway -t 120 -c naf_windows_initiate_audit -a "$Arg"
        CommandResult=$?
        if [ $CommandResult -eq 0 ] ; then
            writelog $Logfile Info "Audit succeeded on ${Target}."
            writelog Output Info "Audit succeeded on ${target}."
            exit 0
        else
            writelog $Logfile Error "Audit failed on $Target, with exit code $CommandResult."
            writelog Output Error "Audit failed on $Target, with exit code $CommandResult."
            exit 1
        fi
    elif [[ $Output == "Logstash" ]] ; then
        Arg="-H \"$Target\" -O \"$Output\" -L \"$LogstashServer\" -p \"$LogstashPort\""
        /usr/local/nagios/libexec/check_nrpe -H $Gateway -t 120 -c naf_windows_initiate_audit -a "$Arg"
        CommandResult=$?
        if [ $CommandResult -eq 0 ] ; then
            writelog $Logfile Info "Audit succeeded on ${Target}."
            writelog Output Info "Audit succeeded on ${target}."
            exit 0
        else
            writelog $Logfile Error "Audit failed on $Target, with exit code ${CommandResult}."
            writelog Output Error "Audit failed on $Target, with exit code ${CommandResult}."
            exit 1
        fi
    fi
elif [[ $IsHostgroup == true ]]; then
    writelog Verbose Info "Audit script started with output $Output on hostgroup ${Target}."
    writelog Output Info "Audit script started with output $Output on hostgroup ${Target}."
    HostMemberList=$(curl -s "$NagiosUser:$NagiosPassword@$NagiosServer/nagios/cgi-bin/objectjson.cgi?query=hostgroup&hostgroup=$Target" | sed -e '1,/members/d' | sed '/]/,+100 d' | tr -d '"' | tr -d ',' | tr -d ' ')
    IFS=$'\n'
    for Hostname in $HostMemberList
    do
        writelog Verbose Info "Audit script started with output $Output on host ${Hostname}."
        writelog Output Info "Audit script started with output $Output on host ${Hostname}."
        Arg="-H \"$Hostname\" -O \"Html\""
        /usr/local/nagios/libexec/check_nrpe -H $Hostname -t 120 -c naf_windows_initiate_audit -a "$Arg"
        CommandResult=$?
        case $CommandResult in
            "0")
                Now=$(date '+%Y-%m-%d %H:%M:%S')
                OutputStringSuccess="${OutputStringSuccess}$Now: $Hostname - "
                ((OutputSuccess+=1))
                writelog Output Info "Audit succeeded on ${Hostname}."
                ;;
            "1")
                Now=$(date '+%Y-%m-%d %H:%M:%S')
                OutputStringFailed=" ${OutputStringFailed}$Now: $Hostname - "
                ((OutputFailed+=1))
                writelog Output Info "Audit failed on $Hostname, with exit code ${CommandResult}."
                ;;
            *)
                Now=$(date '+%Y-%m-%d %H:%M:%S')
                OutputStringUnknown=" ${OutputStringUnknown}$Now: $Hostname: ($?) - "
                ((OutputUnknown+=1))
                writelog Output Info "Audit failed on $Hostname, with exit code ${CommandResult}."
                ;;
        esac
    done
    Now=$(date '+%Y-%m-%d %H:%M:%S')
    OutputTotal=$((OutputSuccess + OutputFailed + OutputUnknown))
    OutputString="$Now: $OutputSuccess / $OutputTotal HOSTS SUCCEEDED! "
    if [[ $OutputFailed -ge 1  ]]; then
        OutputString="${OutputString}FAILED: ${OutputStringFailed}, "
    fi
    if [[ $OutputUnknown -ge 1  ]]; then
        OutputString="${OutputString}UNKNOWN: ${OutputStringUnknown}, "
    fi
    echo "${OutputString}SUCCES: $OutputStringSuccess"
    if [[ $OutputFailed -ge 1  ]]; then
        exit 1
    else
        exit 0
    fi
fi
