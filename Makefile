build:
	rm -f proc_inj
	gcc -o proc_inj main.c

dummy:
	rm -f dummy
	gcc -o dummy dummy.c -Os

clean:
	rm -f proc_inj
	rm -f dummy
	