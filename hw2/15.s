_start:
    call a
    jmp exit

a:
    pop rax
    push rax
    ret

exit: