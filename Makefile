build:
	rm -f proc_inj
	gcc -o proc_inj main.c

extract_shellcode:
	nasm -f elf64 -o shellcode.o main.asm
	objcopy -O binary -j .text shellcode.o shellcode.bin
	xxd -i shellcode.bin > shellcode.c
	cat shellcode.c
	rm shellcode*

dummy:
	rm -f dummy
	gcc -o dummy dummy.c -Os

clean:
	rm -f proc_inj
	rm -f dummy