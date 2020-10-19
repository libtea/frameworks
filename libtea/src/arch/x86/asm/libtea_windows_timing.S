
; See LICENSE file for license and copyright information

; Note: designed for MASM and Windows x64 calling convention only. "Integer values passed in left-to-right order in RCX, RDX, R8, and R9" */

.code

;--------------------------------------------
libtea__windows_counting_thread PROC
  mov rax, 0
  count_loop: inc rax
  mov rax, (rcx)
  jmp count_loop
libtea__windows_counting_thread ENDP


;libtea__windows_rdpru PROC
;  mfence
  ;RDPRU instruction, AMD Zen 2+ only
;  db 0fh
;  db 01h
;  db 0xFD  ;TODO fix MASM doesn't like this one value for some reason
;  mfence
;  mov rax, (rcx)
;  mov rdx, (rdx)
;libtea__windows_rdpru ENDP


END