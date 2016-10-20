#############################################################################
#
#       makefile for bypass adapter server
#
#############################################################################


VPATH = $(BUILD_SRC)
PWD = $(shell pwd)

SRV_SOURCES = ba_server.c t4_switch.c hw_bypass.c
SRV_OBJECTS = ba_server.o t4_switch.o hw_bypass.o
CLI_SOURCES = ba_client.c
CLI_OBJECTS = ba_client.o

LINK_OBJECTS = 

LIBS = 

CFLAGS += -g -Wall -I$(BUILD_SRC) \
		-I$(PWD)/../../../cxgbtool

INCLUDES =	

$(SRV_OBJECTS) : $(INCLUDES) $(SRV_SOURCES) $(BUILD_SRC)/Makefile

$(CLI_OBJECTS) : $(INCLUDES) $(CLI_SOURCES) $(BUILD_SRC)/Makefile

all	: ba_server ba_client $(BUILD_SRC)/Makefile

ba_server :	$(SRV_OBJECTS) $(LIBS) $(LINK_OBJECTS)
		$(CC) $(CFLAGS) $(SRV_OBJECTS) $(LINK_OBJECTS) $(LIBS) -o $@ 

ba_client :	$(CLI_OBJECTS) $(LIBS) $(LINK_OBJECTS)
		$(CC) $(CFLAGS) $(CLI_OBJECTS) $(LINK_OBJECTS) -o $@

install:
	@mkdir -p $(INSTDIR)/bin
	cp -fp ba_server $(INSTDIR)/bin


