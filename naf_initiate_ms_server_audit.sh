#!/bin/bash

# Script name: naf_initiate_ms_server_audit.sh
# Version: 0.15.2.24
# Author: Willem D'Haese
# Created on: 15/09/2014
# Purpose: Quick action bash script that will initiate naf_initiate_ms_server_audit.ps1
# Recent History:
#   15/09/2014 => Inital configuration
#   21/09/2014 => Updated code and documentation
#	24/02/2015 => Cleanup and compatibility with NAF / Reactor
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed 
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public 
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

Hostname=$1
Logfile=/var/log/naf_actions.log
Now=$(date '+%Y-%m-%d -- %H:%M:%S')
echo "$NOW : Audit initiated on $Hostname
/usr/local/nagios/libexec/check_nrpe -H $Hostname -t 300 -c naf_initiate_ms_server_audit -a $Hostname
Exitcode=$?

Now=$(date '+%Y-%m-%d -- %H:%M')

if [ $Exitcode -eq 0 ]
then
        echo "$Now : Audit succeeded on $Hostname, with exit code $Exitcode ." >> $Logfile
else
        echo "$Now : Audit failed on $Hostname, with exit code $Exitcode ." >> $Logfile
fi

exit
