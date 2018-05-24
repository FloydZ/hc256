
bits   64
   
struc pushad_t
  _edi resd 1
  _esi resd 1
  _ebp resd 1
  _esp resd 1
  _ebx resd 1
  _edx resd 1
  _ecx resd 1
  _eax resd 1
  .size:
endstruc

global hc256_generate
global _hc256_generate

global hc256_setkey
global _hc256_setkey

;global hc256_crypt
;global _hc256_crypt

; expects ctx in rdi
hc256_generate:
_hc256_generate:
    push    rdi   ;Save that shit

    xor     rdx, rdx
    mov     dh, 8               ;rdx = 2048
    dec     edx                 ;rdx = 2043
   
    mov     r8d, [rdi]
    mov     eax, r8d            ;save t for later ;Richtig?
    inc     r8d
    and     r8d, edx
    mov     [rdi], r8d
    
    lea     rsi, [rdi+4]        ;pointer to P
    lea     rdi, [rsi+1024*4]     ;pointer to Q
    
    shr     edx, 1              ;edx = 1023
    cmp     eax, edx            ; c->ctr > 1023    
    jbe     gen_l0
    xchg    rsi, rdi            ; swap Q and P ptrs
gen_l0:
    and     eax, edx            ; i &= 1023
    
    lea     ebx, [eax - 3]      ; i3 = (i - 3) & 1023;
    and     ebx, edx            
    
    lea     ecx, [eax - 10]     ; i10 = (i - 10) & 1023;
    and     ecx, edx
    
    mov     r9d, eax            ; i1023 = (i - 1023) & 1023;
    sub     r9d, edx
    and     r9d, edx
    
    mov     r10d, [rsi+rax*4]   ; r10d  = x0[i]
    add     r10d, [rsi+rcx*4]   ; r10d += x0[i10]
    
    mov     r9d, [rsi+r9*4]     ; r9d  = x0[i1023]
    mov     ebx, [rsi+rbx*4]    ; ebx  = x0[i3]
    mov     ecx, ebx            ; ecx  = x0[i3]
    xor     ecx, r9d            ; ecx ^= x0[i1023] (r9d)
    and     ecx, edx            ; ecx &= 0x3ff
    add     r10d, [rdi+rcx*4]   ; ecx  = x1[(x0[i3] ^ x0[i1023]) & 1023]
    ror     ebx, 10             ; ebx  = ROTR32(x0[i3], 10)
    rol     r9d, 9              ; r9d  = ROTL32(x0[i1023], 9)

    xor     ebx, r9d            ;
    add     r10d, ebx           ; r10d = x0[i] += x0[i10] + (ROTR32(x0[i3], 10) ^ ROTL32(x0[i1023], 9)) + x1[(x0[i3] ^ x0[i1023]) & 0x3ff];
    mov     [rsi+rax*4], r10d   ; Save that shit

    lea     r9d, [eax-12]       ; i12 = (i - 12) & 1023;
    and     r9d, edx
    mov     r9d, [rsi+r9*4]     ; r9d = x0[i12]
    
    mov     eax, [rsi+rax*4]    ; r10d  = x0[i]
    inc     edx                 ; rdx = 1024
    
;Now
;eax = w0=x0[i];
;r9d = w1=x0[i12];
    xor     rcx, rcx        ;Mayne too much?        
gen_l1:
    movzx   rbx, r9b             ; &255
    add     ecx, [rdi+rbx*4]     ; r+=
    add     rdi, rdx             ; x1 += 1024/4
    shr     r9d, 8               ; w1 >>= 8
    jnz     gen_l1
    
    xor     eax, ecx

    pop     rdi
    ret

;void hc256_setkey(hc_ctx *c, void *kiv)
hc256_setkey:
_hc256_setkey:
;   rdi = c
;   rsi = kiv
    mov     r12, rsi
    mov     r11, rdi

    xor     ecx, ecx            ; ecx=0
    mul     ecx                 ; eax=0, edx=0
    
    mov     cl, 5               ; ecx=5
    mov     dh, 16              ; edx=4096
    
xalloca:
    sub     rsp, rdx            ; subtract page size
    test    [rsp], rsp          ; page probe
                                ; causes pages of memory to be 
                                ; allocated via the guard page 
                                ; scheme (if possible)
    loop    xalloca             ; raises exception if 
                                ; unable to allocate
    mov     rbx, rsp            ; ebx=W

    ; 2. copy 512-bits of key/iv to workspace
    mov     cl, 64
    mov     rdi, rbx          ; edi=W
    rep     movsb

    mov     rsi, rbx          ; esi=W
    mov     cl, 16
expand_key:
    ; eax = SIG0(W[i-15])
    mov     eax, [rdi - 15*4]
    mov     edx, eax
    mov     r8d, eax
    ror     eax, 7
    ror     edx, 18
    shr     r8d, 3
    xor     eax, edx
    xor     eax, r8d
    ; ebx = SIG1(W[i-2])
    mov     ebx, [rdi - 2*4]
    mov     edx, ebx
    mov     r8d, ebx
    ror     ebx, 17
    ror     edx, 19
    shr     r8d, 10
    xor     ebx, edx
    xor     ebx, r8d
    ; W[i] = ebx + W[i-16] + eax + w[i-7] + i
    add     eax, [rdi - 16*4]
    add     ebx, [rdi -  7*4]
    add     eax, ebx
    add     eax, ecx
    stosd
    inc     ecx
    cmp     ecx, 4096; TODO[rsp]        ; 4096 words
    jnz     expand_key

    
    mov     ecx, 4096 ;TODO opt
    lea     rdi, [r11 + 4]      ;r11 = rdi = c Saved from previous
    shr     ecx, 1
    add     rsi, rcx
    rep     movsd

    mov     rdi, r11
    mov     ecx, 4096       ;Geht auch besser
sk_l3:
    push    rcx ;TODO needs to optimized
    call    hc256_generate
    pop     rcx
    loop    sk_l3
    
    ;free stacl
    ;pop    eax              ; eax=4096
    ;lea    esp, [esp+eax*4] ; free stack
    ;add    esp, eax
    add     rsp, 4096*5

    mov     rsi, r12
    mov     rdi, r11
    ret

;void hc256_crypt(hc_ctx *c, void *in, uint32_t inlen)
hc256_crypt1:
_hc256_crypt1:
    push    rsi
    push    rdi
    mov     rcx, rdx
hc_l0:                       ; .repeat
    jecxz   hc_l2             ; .break .if ecx == 0
    push    rcx
    push    rdi   ;Save that shit
    call    hc256_generate
    pop     rdi
    pop     rcx
hc_l1:
    mov     r8d, eax
    and     r8, 0xFF
    xor     [rsi], r8d         ; *in ^= (w0 & 0xFF)
    inc     rsi               ; in++
    shr     eax, 8            ; w0 >>= 8
    loopnz  hc_l1             ; .while ecx != 0 && eax != 0
    jmp     hc_l0
hc_l2:
    pop     rdi
    pop     rsi
    ret
