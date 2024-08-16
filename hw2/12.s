mov eax, [0x600000]
mov ebx, 5
mul ebx
mov ebx, [0x600004]
sub ebx, 3

xor edx, edx
div ebx

mov [0x600008], eax