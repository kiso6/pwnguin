#!/usr/bin/bash

searchsploit --nmap "./run/detect.xml" -j 2> /dev/null | grep -Pzo '{\n\t[\s\S]*?\n}' |  tr '\0' ',' > temp.txt && mv temp.txt ./run/exploit_list
# finalize the Parse the JSON, testing if file is empty
if [ -s "./run/exploit_list" ]; then
    # file not empty
    sed '$ s/.$/]/' ./run/exploit_list > temp.txt && mv temp.txt ./run/exploit_list
    echo "[" | cat - ./run/exploit_list > temp.txt && mv temp.txt ./run/exploit_list
else
    # file empty
    echo "[]" > ./run/exploit_list
fi
