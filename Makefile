all:
	gcc -O -g tcpip.c tapdev.c
clean:
	rm -rf a.out cscope.* tags
