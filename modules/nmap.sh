#!/usr/bin/bash

nmap -oX "detect.xml" -sV $1 -v
