exit_shellcode: exit_shellcode.o
	ld -m elf_i386 -o exit_shellcode exit_shellcode.o
exit_shellcode.o: exit_shellcode.asm
	nasm -f elf32 -o exit_shellcode.o exit_shellcode.asm
