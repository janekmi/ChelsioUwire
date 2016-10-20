#########################################################################
# common defines and flags shared between klib and ulib
#########################################################################
ifndef AR
AR = /usr/bin/ar
endif

ifndef RM
RM = /bin/rm
endif

TMPOUT := testcc
try-run = $(shell set -e;	\
	TMP="$(TMPOUT).$$$$.tmp";	\
	if ($(1)) >/dev/null 2>&1;	\
	then echo "$(2)";		\
	else echo "$(3)";		\
	fi;				\
	rm -f "$$TMP")

cc-option = $(call try-run,\
	$(CC) $(1) -S -xc /dev/null -o "$$TMP",$(1),$(2))

COMMON_CFLAGS	+= -g 
COMMON_CFLAGS	+= -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer \
			-Wno-sign-compare \
			-Wundef -Wno-trigraphs \
			-fno-strict-aliasing -fno-common \
			-ffreestanding
COMMON_CFLAGS	+= $(call cc-option,-fno-stack-protector)
# warn about C99 declaration after statement
COMMON_CFLAGS += $(call cc-option,-Wdeclaration-after-statement,)
# disable pointer signedness warnings in gcc 4.0
COMMON_CFLAGS += $(call cc-option,-Wno-pointer-sign,)
# silence unused variable warnings in gcc 4.6
COMMON_CFLAGS += $(call cc-option,-Wno-unused-but-set-variable,)
