_start:
    test eax, eax
    setge al
    movzx eax, al
    or eax, eax
    jnz pos1
    mov eax, -1
pos1:
    mov [0x600000], eax

    test ebx, ebx
    setge bl
    movzx ebx, bl
    or ebx, ebx
    jnz pos2
    mov ebx, -1
pos2:
    mov [0x600004], ebx

    test ecx, ecx
    setge cl
    movzx ecx, cl
    or ecx, ecx
    jnz pos3
    mov ecx, -1
pos3:
    mov [0x600008], ecx

    test edx, edx
    setge dl
    movzx edx, dl
    or edx, edx
    jnz pos4
    mov edx, -1
pos4:
    mov [0x60000c], edx
