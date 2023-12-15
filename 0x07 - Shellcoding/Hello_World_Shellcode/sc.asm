[bits 32]
[section .text]

global _start

_start:

mini_hello:
  xor ebx,ebx
  mul ebx
  mov al,0x0a
  push eax
  push 0x646c726f
  push 0x57202c6f
  push 0x6c6c6548
  mov al,4
  mov bl,1
  mov ecx,esp
  mov dl,13
  int 0x80
  mov al,1
  xor ebx,ebx
  int 0x80
