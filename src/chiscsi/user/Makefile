SHELL = /bin/bash

COMMON_OBJS := $(patsubst %.c,%.o,$(wildcard common/*.c))
ifeq ($(srculib),1)
  LIBOBJ := $(patsubst %.c,%.o,$(wildcard ulib/*.c))
  LIBINC += -I. -I../includes -I../includes/common -I../private/include
else
  LIBOBJ = ../lib/ulib/libchctl.$(ARCH).a
endif

CFLAGS += -g
#CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes
CFLAGS += $(LIBINC)

ISCSICTL = iscsictl
ISCSICTL_OBJS := $(patsubst %.c,%.o,$(wildcard cli/*.c))

CHISNS = chisns
CHISNS_LIBS	= -lpthread
CHISNS_OBJS	:= $(patsubst %.c,%.o,$(wildcard isns/*.c))

all: $(ISCSICTL) $(CHISNS)

iscsictl: $(ISCSICTL_OBJS) $(COMMON_OBJS) $(LIBOBJ)
	$(CC) $^ -o $@

chisns: $(CHISNS_OBJS) $(COMMON_OBJS) $(LIBOBJ)
	$(CC) $^ -o $@ $(CHISNS_LIBS)

clean:
	@rm -f *.o */*.o  $(ISCSICTL) $(CHISNS)
