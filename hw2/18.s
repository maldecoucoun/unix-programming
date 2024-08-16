mov rax, 1
mov rbx, 0
mov rdx, 28

r:
    mov rcx, rax
    imul rbx, 3
    imul rax, 2
    add rax, rbx
    mov rbx, rcx

    dec rdx
    cmp rdx, 1
    jne r
