exploit: ./xpl.c ./create-libc.py
	python3 ./create-libc.py
	gcc xpl.c -o xpl

debug: ./xpl ./gdb-script
	gdb -ix gdb-script

test: ./xpl.c ./create-libc.py
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
	python3 ./create-libc.py
	gcc xpl.c -DNO_ASLR -o xpl

clean:
	rm ./xpl
	rm -rf \"
