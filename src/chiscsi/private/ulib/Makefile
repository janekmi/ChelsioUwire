ifeq ($(PLATFM),)
  PLATFM = $(shell uname -m | sed -e s/i.86/i386/)
endif

ifeq ($(PLATFM), arm)
  RULES = arm_sfp arm_hfp
endif

ifeq ($(PLATFM), ppc64)
  RULES = ppc64
endif

ifeq ($(PLATFM), ppc)
  RULES = ppc
endif

ifeq ($(PLATFM),i386)
  RULES = arch32
endif
ifeq ($(PLATFM),x86_64)
  RULES = arch64
  ifneq ($(wildcard /usr/include/gnu/stubs-32.h),)
    RULES += arch32
  endif
endif

default: dir $(RULES)

dir:
	mkdir -p ../../lib/ulib

arch32: dir
	$(RM) *.o
	$(MAKE) -f make32

arch64: dir
	$(RM) *.o
	$(MAKE) -f make64

ppc: dir
	$(RM) *.o
	$(MAKE) -f make_ppc

ppc64: dir
	$(RM) *.o
	$(MAKE) -f make_ppc64

arm_sfp: dir
	$(RM) *.o
	$(MAKE) -f make_arm FPU=0

arm_hfp: dir
	$(RM) *.o
	$(MAKE) -f make_arm FPU=1

clean:
	$(MAKE) -f make32 clean
	$(MAKE) -f make64 clean
	$(MAKE) -f make_ppc clean
	$(MAKE) -f make_arm FPU=0 clean
	$(MAKE) -f make_arm FPU=1 clean
