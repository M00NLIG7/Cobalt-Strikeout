CC=gcc
CFLAGS=-I./include
OBJ=main.o src/audit.o src/discovery.o src/hardening.o src/network.o src/system.o

all: main

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f main $(OBJ)
    rm -f *.o
