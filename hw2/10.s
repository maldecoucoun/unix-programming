mov eax, [0x600000]
mov ebx, [0x600004]
add eax, ebx
mov ebx, [0x600008]
mul ebx
mov [0x60000c], eax