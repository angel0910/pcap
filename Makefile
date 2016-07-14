test: test.c
	gcc -o test test.c -lpcap

clean:
	rm test

