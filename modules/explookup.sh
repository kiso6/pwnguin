#!/usr/bin/bash

searchsploit --nmap "detect.xml" -j 2> /dev/null | grep -Pzo '{\n\t[\s\S]*?\n}' |  tr '\0' ',' > temp.txt && mv temp.txt exploit_list
# finalize the Parse the JSON, testing if file is empty
if [ -s "exploit_list" ]; then
    # file not empty
    sed '$ s/.$/]/' exploit_list > temp.txt && mv temp.txt exploit_list
    echo "[" | cat - exploit_list > temp.txt && mv temp.txt exploit_list
else
    # file empty
    echo "[]" > exploit_list
fi
