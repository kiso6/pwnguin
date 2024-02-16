#!/usr/bin/bash

rm -rf build
rm -rf dist
pyinstaller -d all --onefile autopwn.py
cp dist/autopwn .
