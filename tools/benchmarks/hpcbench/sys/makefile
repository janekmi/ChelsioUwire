# A simple make file for sysmon

CC = gcc
all: sysmon
sysmon: sysmon.c util.c util.h
	$(CC) -Wall util.c sysmon.c -o sysmon
clean: 
	rm -rf *.o core 
cleanall:
	rm -rf *.o *~ core sysmon
