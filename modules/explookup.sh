#!/usr/bin/bash

nmap -oX "detect.xml" -sV -O $1
searchsploit --nmap "detect.xml" -j | grep -eP "Metasploit" >> "exploit_list"
