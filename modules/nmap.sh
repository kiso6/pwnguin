#!/usr/bin/bash

nmap -oX "./run/detect.xml" -sV $1 -v
