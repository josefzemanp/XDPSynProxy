CLANG ?= clang
CFLAGS = -O2 -g -Wall -target bpf

all:
	$(CLANG) $(CFLAGS) -c xdp_prog.c -o xdp_prog.o
clean:
	rm -f *.o
