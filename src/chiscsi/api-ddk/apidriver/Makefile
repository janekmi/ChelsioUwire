# Makefile for the API development examples */
KERN_RELEASE := $(shell uname -r)
PWD := $(shell pwd)

#Support for makefile for ppc
ifeq ($(PLATFM),ppc)
CROSS_COMPILE   ?= ppc_4xx-

AS              = $(CROSS_COMPILE)as
LD              = $(CROSS_COMPILE)ld
CC              = $(CROSS_COMPILE)gcc
CPP             = $(CC) -E
AR              = $(CROSS_COMPILE)ar
NM              = $(CROSS_COMPILE)nm
STRIP           = $(CROSS_COMPILE)strip
OBJCOPY         = $(CROSS_COMPILE)objcopy
OBJDUMP         = $(CROSS_COMPILE)objdump

endif

ifeq ($(KDIR),)
        KDIR ?= /lib/modules/$(KERN_RELEASE)/build
else
        override KDIR := $(shell cd $(KDIR) && pwd)
endif

#Includes from chiscsi.v5
ifeq ($(CHDIR), )
      $(error Variable CHDIR is not set. Run " . ./configure")
endif

KINCS += -I$(CHDIR)/includes/

KDEFS += -g
#KDEFS += -D__REDIRECTION_TEST__ 
#KDEFS += -D__CHAP_TEST__

EXTRA_CFLAGS += $(KINCS) $(KDEFS)

obj-m := ifacedriver.o 
	ifacedriver-objs := iface_init.o iface_target_class.o iface_utils.o storage_driver.o iface_lun_class.o storage_kthread.o

all:default

default: ifacedriver

ifacedriver:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	 rm -rf *.ko *.o *.mod.o Module.* modules.* ifacedriver.mod.c .tmp_versions/ .ifacedriver.* .*.o.cmd
