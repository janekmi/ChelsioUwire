# Makefile for Chelsio T4 firmware.
# Copyright (c) 2006-2008 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

override base_t4 = t4fw-
override base_t5 = t5fw-
override suff = .bin
override default_fwdir = /lib/firmware
override configfile_t4 = t4-config.txt
override configfile_t5 = t5-config.txt
override aq1202phyfirmware = aq1202_fw.cld
override bcm8483firmware = bcm8483.bin

# Find a directory for the image to be installed.
ifeq ($(KERNELRELEASE),$(utsrelease))
  # If the target is this machine, find the firmware location.
  fwdir := $(strip $(shell sed '/^FIRMWARE_DIR\s*=/!d;s/FIRMWARE_DIR\s*=//' \
                           2>/dev/null < /etc/hotplug/firmware.agent))
  fwdir += /lib/firmware /lib/firmware/$(utsrelease) /usr/lib/hotplug/firmware
  fwdir := $(firstword $(wildcard $(fwdir)))
  ifeq ($(fwdir),)
    fwdir := $(default_fwdir)
  endif
else
  # Otherwise, just use default, there's no way of knowing.
  fwdir := $(default_fwdir)
endif

# The driver is looking for the FW under $FIRMWARE_DIR/cxgb4.
# fixup firmware directory.
fixup_fwdir := $(fwdir)/cxgb4

# Get the latest T4 firmware image in the package.
fwfile_t4 := $(firstword $(shell /bin/ls $(base_t4)*$(suff) |\
                              sed 's/$(base_t4)//' | sort -nr))
ifneq ($(fwfile_t4),)
  fwfile_t4 := $(base_t4)$(fwfile_t4)
endif

# Get the latest T5 firmware image in the package.
fwfile_t5 := $(firstword $(shell /bin/ls $(base_t5)*$(suff) |\
                              sed 's/$(base_t5)//' | sort -nr))
ifneq ($(fwfile_t5),)
  fwfile_t5 := $(base_t5)$(fwfile_t5)
endif

.PHONY: default
default: install

.PHONY: install
install:
	@if [ -z "$(fwfile_t4)" ]; then \
	   echo "*** ERROR: No T4 firmware image to install." >&2;\
	   exit 0;\
	 fi;

	@if [ -z "$(fwfile_t5)" ]; then \
	   echo "*** ERROR: No T5 firmware image to install." >&2;\
	   exit 0;\
	 fi;

	@if ! [ -d "$(fwdir)" ]; then \
	   echo "*** ERROR: No directory to install firmware." >&2;\
	   exit 0;\
	 fi;\

	 install -D $(verbose) -m 644 $(fwfile_t4) $(fixup_fwdir)/$(fwfile_t4);
	 install -D $(verbose) -m 644 $(fwfile_t5) $(fixup_fwdir)/$(fwfile_t5);
	 /bin/ln -sf $(fixup_fwdir)/$(fwfile_t4) $(fixup_fwdir)/t4fw.bin
	 /bin/ln -sf $(fixup_fwdir)/$(fwfile_t5) $(fixup_fwdir)/t5fw.bin
	 install -D $(verbose) -m 644 $(configfile_t4) $(fixup_fwdir)/$(configfile_t4);
	 install -D $(verbose) -m 644 $(configfile_t5) $(fixup_fwdir)/$(configfile_t5);
	 install -D $(verbose) -m 644 $(aq1202phyfirmware) $(fixup_fwdir)/$(aq1202phyfirmware);
	 install -D $(verbose) -m 644 $(bcm8483firmware) $(fixup_fwdir)/$(bcm8483firmware);

.PHONY: uninstall
uninstall:
	@-if [ -n "$(verbose)" ]; then \
	    echo "Removing $(fixup_fwdir)/$(fwfile_t4)";\
	    echo "Removing $(fixup_fwdir)/$(fwfile_t5)";\
	  fi;\
	  /bin/rm -f $(fixup_fwdir)/$(fwfile_t4) 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/$(fwfile_t5) 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/t4fw.bin 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/t5fw.bin 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/$(configfile_t4) 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/$(configfile_t5) 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/$(aq1202phyfirmware) 2>/dev/null;
	  /bin/rm -f $(fixup_fwdir)/$(bcm8483firmware) 2>/dev/null;
