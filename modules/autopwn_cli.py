#!/bin/python3

import autopwn
import argparse

parser = argparse.ArgumentParser("autopwn_cli.py")
parser.add_argument('--tgt')
parser.add_argument('--loc')
args = parser.parse_args()

print(args.tgt)
print(args.loc)

