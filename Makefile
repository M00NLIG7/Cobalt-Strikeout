CC=gcc
CFLAGS=-I./include -std=gnu99 -static /usr/lib64/libc.a
OBJ=main.o src/audit.o src/discovery.o src/hardening.o src/network.o src/system.o

all: main

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f main $(OBJ)
