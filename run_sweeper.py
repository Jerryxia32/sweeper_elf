#!/usr/bin/env python3

import sys
import subprocess

bw = 0
usec = 0
REPEAT = 20

filenames = sys.argv[1:]
for filename in filenames:
    for _ in range(REPEAT):
        result = subprocess.run(['./sweeper_elf', filename], stdout=subprocess.PIPE).stdout.decode()
        usec += float(result.split()[1])
        bw += float(result.split()[3])

print(usec/len(filenames)/REPEAT)
print(bw/len(filenames)/REPEAT)
