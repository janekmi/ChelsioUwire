# A simple make file for tcptest and tcpserver

# Sun Solaris
# LIBS = -lsocket -lnsl

# Linux
LIBS =

CC = gcc

all: tcpserver tcptest

tcpserver: tcplib.h tcplib.c util.h util.c tcpserver.c
	$(CC) -O3 -Wall util.c tcplib.c tcpserver.c -o tcpserver $(LIBS)

tcptest: tcplib.h tcplib.c util.h util.c tcptest.c
	$(CC) -O3 -Wall util.c tcplib.c tcptest.c -o tcptest $(LIBS) 

debug: tcpserver.c tcptest.c tcplib.c tcplib.h util.c util.h
	$(CC) -O3 -DDEBUG -g util.c tcplib.c tcpserver.c -o tcpserver $(LIBS)
	$(CC) -O3 -DDEBUG -g util.c tcplib.c tcptest.c -o tcptest $(LIBS) 

clean: 
	rm -rf *.o core 

cleanall:
	rm -rf *.o *~ core tcpserver tcptest

