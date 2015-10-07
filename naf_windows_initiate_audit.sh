#!/bin/bash

# Script name: 	naf_initiate_ms_server_audit.sh
# Version: 		v1.08.151007
# Created on: 	15/09/2014
# Author: 		Willem D'Haese
# Purpose: 		Initiates audit of a Windows host and output to Html or Logstash
# Recent History:
#   15/09/14 => Inital configuration
#   21/09/14 => Updated code and documentation
#	24/02/15 => Cleanup and compatibility with NAF / Reactor
#	07/10/15 => Inserted writelog and test audit result exitcode
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

Hostname=$1
Output=$2

Logfile=/var/log/naf_actions.log
Verbose=0

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

writelog Verbose Info "Audit initiated on $Hostname"

Arg="-H \"$Hostname\" -O \"$Output\""
/usr/local/nagios/libexec/check_nrpe -H $Hostname -t 300 -c naf_initiate_ms_server_audit -a  "$Arg"
CommandResult=$?
if [ $CommandResult -eq 0 ]; then
    writelog $Logfile Info "Audit succeeded on $Hostname."
    writelog Output Info "Audit succeeded on $Hostname."
    exit 0
else
    writelog $Logfile Error "Audit failed on $Hostname, with exit code $Exitcode."
    writelog Output Error "Audit failed on $Hostname, with exit code $Exitcode."
    exit 1
fi

