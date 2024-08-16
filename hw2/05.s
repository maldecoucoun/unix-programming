mov     cx, 16            
mov     bx, ax            
lea     rdi, [0x600000]   
add     rdi, 15           

convert_loop:
    mov     ax, bx            
    and     ax, 1             
    add     ax, '0'           
    mov     [rdi], al         
    shr     bx, 1             
    dec     rdi              
    loop    convert_loop