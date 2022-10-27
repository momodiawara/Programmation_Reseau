CC=gcc

CFLAGS=-Wall -g -std=gnu99

LDLIBS= -lm

ALL = fichier sha224-256.o

all : $(ALL)

sha224-256.o : sha224-256.c

fichier : fichier.c sha224-256.o

clear:
	rm -rf *~
clean :
	rm -rf *~  *.o *.exe *.exe.stackdump $(ALL)
