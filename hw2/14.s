mov     eax, [0x600000]
mov     ecx, [0x600008]

sub     ecx, ebx

mov     ebx, [0x600004]
neg     ebx
imul    eax, ebx

cdq
idiv ecx

mov [0x600008], eax