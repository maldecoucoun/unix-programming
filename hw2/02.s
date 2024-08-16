_start:
    mov ecx, 9

outer_loop:
    mov ebx, ecx

inner_loop:
    xor esi, esi

next_comparison:
    mov eax, [0x600000 + esi*4]
    mov edx, [0x600000 + esi*4 + 4]
    cmp eax, edx
    jle no_swap

    mov [0x600000 + esi*4], edx
    mov [0x600000 + esi*4 + 4], eax

no_swap:
    add esi, 1
    cmp esi, ebx
    jl next_comparison

    dec ebx
    cmp ebx, 0
    jg inner_loop

    dec ecx
    jnz outer_loop

    mov eax, 1
    xor edi, edi

