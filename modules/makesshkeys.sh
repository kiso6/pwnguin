#!/usr/bin/bash

id_rsa=~/.ssh/id_rsa.pub
if [ ! -f "$id_rsa" ]; then
    yes ''| ssh-keygen
fi
cp ~/.ssh/id_rsa.pub post/.
