sc: sc.o
	ld -m elf_i386 -o sc sc.o
sc.o: sc.asm
	nasm -f elf32 -o sc.o sc.asm
