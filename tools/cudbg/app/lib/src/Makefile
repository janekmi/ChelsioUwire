LIBDIR=..
INCLUDE= -I. -I../inc -I/usr/include/  \
	 -I../../include/

CFLAGS= -D_GNU_SOURCE  $(INCLUDE)
LIBS =

ifeq ($(CUDBG_FLAGS), utils)
	CFLAGS +=-DCUDBG_UTILS
endif

ifeq ($(LIBTYPE), static)
	CFLAGS +=
else
	CFLAGS +=-fPIC #-Wall -Werror
endif

all: clean libcudbg.so
OBJ=  cudbg_lib.o fastlz_api.o fastlz.o cudbg_view.o cudbg_wtp.o cudbg_flash_utils.o cudbg_common.o
libcudbg.so: $(OBJ)

ifeq ($(LIBTYPE), static)
	ar rcs libcudbg.a $(OBJ)
else
	$(CC)  -L./  -shared -Wl,-soname,libcudbg.so  -g -o libcudbg.so $(OBJ)
endif

ifeq ($(LIBTYPE), static)
	cp -p libcudbg.a $(LIBDIR)
else
	cp -p libcudbg.so $(LIBDIR)
endif

clean:
	rm -fr *.o libcudbg.so  libcudbg.a $(LIBDIR)/libcudbg.so $(LIBDIR)/libcudbg.a
