#SHELL += -x
#####################################################################
# supported architecture:
# - i386, compile with and without regparm
# - x64
# - ppc
# - ppc64
# - arm, with and without FPU
#
# compile option:
# - enable_lm=<0|1>     enable lunmasking support
# - enable_bl=<0|1>     enable blanket license support
#
#####################################################################
ifeq ($(PLATFM),)
  PLATFM = $(shell uname -m | sed -e s/i.86/i386/)
endif

ifeq ($(PLATFM),arm)
  RULES = arm
endif
ifeq ($(PLATFM),ppc64)
  RULES = ppc64
endif
ifeq ($(PLATFM),ppc)
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

ifeq ($(enable_bl),1)
  bl_max := 2
else
  bl_max := 1
endif

ifeq ($(enable_lm),1)
  lm_max := 2
else
  lm_max := 1
endif

$(warning RULES = $(RULES),bl = $(bl_max),lm = $(lm_max).)

default: $(RULES)

arch32:
	@-regparm=0 ; while [[ $$regparm -lt 2 ]] ; do \
	scst=0 ; while [[ $$scst -lt 2 ]] ; do \
	lm=0 ; while [[ $$lm -lt $(lm_max) ]] ; do \
	bl=0 ; while [[ $$bl -lt $(bl_max) ]] ; do \
		echo "i386 BL=$$bl SCST=$$scst LUNMASK=$$lm REGPARM=$$regparm" ; \
		$(MAKE) -f make32 BL=$$bl SCST=$$scst LUNMASK=$$lm REGPARM=$$regparm; \
		((bl = bl + 1)) ; \
		done ; \
		((lm = lm + 1)) ; \
		done ; \
		((scst = scst + 1)) ; \
	done; \
		((regparm = regparm + 1)) ; \
	done

# x64
arch64:
	@-scst=0 ; while [[ $$scst -lt 2 ]] ; do \
	lm=0 ; while [[ $$lm -lt $(lm_max) ]] ; do \
	bl=0 ; while [[ $$bl -lt $(bl_max) ]] ; do \
		echo "x64 BL=$$bl SCST=$$scst LUNMASK=$$lm" ; \
		$(MAKE) -f make64 BL=$$bl SCST=$$scst LUNMASK=$$lm; \
		((bl = bl + 1)) ; \
		done ; \
		((lm = lm + 1)) ; \
		done ; \
		((scst = scst + 1)) ; \
	done

ppc:
	@-scst=0 ; while [[ $$scst -lt 2 ]] ; do \
	lm=0 ; while [[ $$lm -lt $(lm_max) ]] ; do \
	bl=0 ; while [[ $$bl -lt $(bl_max) ]] ; do \
		echo "ppc BL=$$bl SCST=$$scst LUNMASK=$$lm" ; \
		$(MAKE) -f make_ppc BL=$$bl SCST=$$scst LUNMASK=$$lm; \
		((bl = bl + 1)) ; \
		done ; \
		((lm = lm + 1)) ; \
		done ; \
		((scst = scst + 1)) ; \
	done

ppc64:
	@-scst=0 ; while [[ $$scst -lt 2 ]] ; do \
	lm=0 ; while [[ $$lm -lt $(lm_max) ]] ; do \
	bl=0 ; while [[ $$bl -lt $(bl_max) ]] ; do \
		echo "ppc64 BL=$$bl SCST=$$scst LUNMASK=$$lm" ; \
		$(MAKE) -f make_ppc64 BL=$$bl SCST=$$scst LUNMASK=$$lm; \
		((bl = bl + 1)) ; \
		done ; \
		((lm = lm + 1)) ; \
		done ; \
		((scst = scst + 1)) ; \
	done

arm:
	@-fpu=0 ; while [[ $$fpu -lt 2 ]] ; do \
	scst=0 ; while [[ $$scst -lt 2 ]] ; do \
	lm=0 ; while [[ $$lm -lt $(lm_max) ]] ; do \
		echo "arm SCST=$$scst LUNMASK=$$lm FPU=$$fpu" ; \
		$(MAKE) -f make_arm SCST=$$scst LUNMASK=$$lm FPU=$$fpu; \
		((lm = lm + 1)) ; \
		done ; \
		((scst = scst + 1)) ; \
	done; \
		((fpu = fpu + 1)) ; \
	done

clean:
	$(RM) -f libchiscsi.*.a 
	@for dir in `find -type d`; do \
	  $(RM) $$dir/*.o; \
	done;
	$(RM) -f ../../lib/klib/libchiscsi.*.a
