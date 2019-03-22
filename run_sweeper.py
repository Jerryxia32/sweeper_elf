#!/usr/bin/env python3

import sys
import subprocess

bw = 0
REPEAT = 20

filenames = sys.argv[1:]
for filename in filenames:
    for _ in range(REPEAT):
        result = subprocess.run(['./sweeper_elf', filename], stdout=subprocess.PIPE).stdout.decode()
        bw += float(result.split()[3])

print(bw/len(filenames)/REPEAT)
