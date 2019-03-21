#!/usr/bin/env python3

import sys
import subprocess

total_ms = 0
REPEAT = 20

filenames = sys.argv[1:]
for filename in filenames:
    for _ in range(REPEAT):
        result = subprocess.run(['./sweeper_elf', filename], stdout=subprocess.PIPE).stdout.decode()
        total_ms += int(result.split()[2])

print(total_ms/len(filenames)/REPEAT)
