_start:
    lea rsi, [0x600000]
    lea rdi, [0x600010] 
    mov rcx, 15          

s:
    mov al, [rsi]       
    cmp al, 65         
    jb next             
    cmp al, 90         
    ja next              
    add al, 32           

next:
    mov [rdi], al        
    inc rsi              
    inc rdi              
    loop s  