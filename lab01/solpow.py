#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import time
import sys
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1]
    print(time.time(), "solving pow ...")
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest()
        if h[:6] == '000000':
            solved = str(i).encode()
            print("solved =", solved)
            break
    print(time.time(), "done.")
    r.sendlineafter(b'string S: ', base64.b64encode(solved))


def solve_arithmetic_challenge(r):
    msg = r.recvuntil(b'? ').decode()
    print(msg)
    p = msg.split(":")[1][:-4]
    print('---')
    # print(p)
    pr = base64.b64decode(p).decode()
    print(pr)
    # Split the ASCII art into lines
    lines = pr.strip().split('\n')

    # Define the start and end indices for each unit
    unit_indices = [
        (0, 6),
        (7, 13),
        (14, 20),
        (21, 27),
        (28, 34),
        (35, 41),
        (42, 48)
    ]

    # Extract each unit
    units = []
    for start, end in unit_indices:
        unit = ""
        for line in lines:
            unit += line[start:end].replace(' ', '')
        units.append(unit)

    # Print each unit
    problem = ''
    for i, unit in enumerate(units, 1):
        # print(f"Unit {i}:\n{unit}\n")
        if unit in '┌───┐│││││':
            problem+='7'
        elif unit in '┌───┐││││││└───┘':
            problem+='0'
        elif unit in '─┐│││─┴─':
            problem+='1'
        elif unit in '┌───┐│┌───┘│└───┘':
            problem+='2'
        elif unit in '┌───┐│───┤│└───┘':
            problem+='3'
        elif unit in '││││└───┤││':
            problem+='4'
        elif unit in '┌────│└───┐│└───┘':
            problem+='5'
        elif unit in '┌───┐│├───┐││└───┘':
            problem+='6'        
        elif unit in '┌───┐││├───┤││└───┘':
            problem+='8'
        elif unit in '┌───┐││└───┤│└───┘':
            problem+='9'
        elif unit in '│──┼──│':
            problem+='+'
        elif unit in '•─────•':
            problem+='/'
        elif unit == '╲╱╳╱╲':
            problem+='*'
        elif unit in '─────':
            problem+='-'

    print(problem)
    x = str(int(eval(problem)))
    print(x)
    r.send(x + '\n')

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10681)
    solve_pow(r)
    # r.interactive()
    msg_prefix = r.recvuntil(b'Please complete').decode()
    print(msg_prefix)
    challenge_count_msg = r.recvline().decode()
    print(challenge_count_msg)
    challenge_count = int(re.findall('[0-9]+', challenge_count_msg)[0])
    print("Challenges count:", challenge_count)

    for i in range(challenge_count):
        solve_arithmetic_challenge(r)

    print(r.recvline().decode())
    r.close()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
