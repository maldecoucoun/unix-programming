mov eax, [0x600000]
mov ebx, [0x600004]
mov ecx, [0x600008]

imul eax, eax, -5
neg ebx
cdq
idiv ecx

mov ecx, edx
cdq
idiv ecx

mov [0x60000c], eax