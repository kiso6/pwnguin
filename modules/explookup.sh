#!/usr/bin/bash

nmap -oX "detect.xml" -sV $1
searchsploit --nmap "detect.xml" -j | grep -Pzo '{\n\t[\s\S]*?\n}' |  tr '\0' ',' | sed '$ s/.$/]/' > temp.txt && mv temp.txt exploit_list
# finalize the Parse the JSON
echo "[" | cat - exploit_list > temp.txt && mv temp.txt exploit_list

