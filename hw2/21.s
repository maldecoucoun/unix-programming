_start:
    mov eax, [0x600000]
    cmp eax, 'a'
    jl not_lowercase
    cmp eax, 'z'
    jg not_lowercase
    sub eax, 32
not_lowercase:
    mov [0x600001], al