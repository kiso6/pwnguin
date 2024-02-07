#!/usr/bin/bash

nmap -oX "detect.xml" -sV -O $1 -vv 
searchsploit --nmap "detect.xml" -j | grep "Metasploit" >> "exploit_list"
cat "exploit_list"