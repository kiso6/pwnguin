#!/bin/bash


hash=$(echo $1 | base64 | sha256sum);
NAME=${hash::20}
openssl enc -e -aes-256-ctr -pbkdf2 -k mypassword -in $1 -out "$NAME.sh"

