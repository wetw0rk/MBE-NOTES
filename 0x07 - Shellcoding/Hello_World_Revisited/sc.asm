[bits 32]
[section .text]

global _start

_start:

user_code:
  jmp message
write_str:
  xor eax,eax
  xor ebx,ebx
  xor edx,edx
  mov al,4    ; Syscall = 4    (Write)
  mov bl,1    ; Output FD = 1  (STDOUT)
  pop ecx     ; Buffer = "Hello, World\n"
  mov dl,13   ; Bytes to write = 13
  int 0x80
  mov al,1
  xor ebx,ebx
  int 0x80
message:
  call write_str
  db "Hello, World",10
