#!/bin/bash

# Script name: naf_initiate_ms_server_audit.sh
# Version: 0.14.9.21
# Author: Willem D'Haese
# Created on: 15/09/2014
# Purpose: Quick action bash script that will initiate naf_initiate_ms_server_audit.ps1
# History:
#       15/09/2014 => Inital configuration
#       21/09/2014 => Updated code and documentation
# Copyright:
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.You should have received a copy of the GNU
# General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

HOSTNAME=$1
LOGFILE=/var/log/naf_initiate_ms_server_audit.log
NOW=$(date '+%Y-%m-%d -- %H:%M:%S')
echo "$NOW : Audit initiated on $HOSTNAME." >> $LOGFILE

/usr/local/nagios/libexec/check_nrpe -H $HOSTNAME -t 300 -c naf_initiate_ms_server_audit -a $HOSTNAME
EXITCODE=$?

NOW=$(date '+%Y-%m-%d -- %H:%M')

if [ $EXITCODE -eq 0 ]
then
        echo "$NOW : Audit succeeded on $HOSTNAME, with exit code $EXITCODE ." >> $LOGFILE
else
        echo "$NOW : Aduit failed on $HOSTNAME, with exit code $EXITCODE ." >> $LOGFILE
fi

exit
