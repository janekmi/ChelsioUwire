# A simple make file for udptest and udpserver

# Sun Solaris 
# LIBS = -lsocket -lnsl

# Linux
LIBS = 

CC = gcc

all: udptest udpserver

debug: udpdebug

udpserver: udplib.c udpserver.c util.c udplib.h util.h
	$(CC) -O3 -Wall util.c udplib.c udpserver.c -o udpserver $(LIBS)

udptest: udplib.c udptest.c util.c udplib.h util.h
	$(CC) -O3 -Wall util.c udplib.c udptest.c -o udptest $(LIBS)

udpdebug: udpserver.c udplib.c udptest.c util.c udplib.h util.h
	$(CC) -O3 -DDEBUG -g util.c udplib.c udpserver.c -o udpserver $(LIBS) 
	$(CC) -O3 -DDEBUG -g util.c udplib.c udptest.c -o udptest $(LIBS) 

clean: 
	rm -rf *.o core 
cleanall:
	rm -rf *.o *~ core udptest udpserver
