all: sock_example.c
	gcc -I/home/buzz/xdp-tutorial/lib/install/include -o sock_example sock_example.c /home/buzz/xdp-tutorial/lib/install/lib/libbpf.a -lelf -lz
clean:
	rm sock_example
