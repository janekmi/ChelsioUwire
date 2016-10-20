DEFS =
DEBUG = -g
CFLAGS = -O2 -Wall -Wno-unused-function $(DEBUG) $(DEFS)
INCLUDES = -I./ \
  	   -Iinclude \
	   -Ilib/inc

LIBFLAG=LIBTYPE=static

PROGS = cudbg_app

CUDBG_APP_OBJ = cudbg_app.o

all: clean $(PROGS)

cudbg_app: $(CUDBG_APP_OBJ)
ifeq ($(LIBTYPE), shared)
	make -C lib/src
else
	make -C lib/src $(LIBFLAG) CUDBG_FLAGS=utils 
endif
	$(CC) $(LDFLAGS) $(CUDBG_APP_OBJ) -Llib -lcudbg \
			$(INCLUDES) $(DEBUG) -o cudbg_app 
.c.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<

clean:
	make -C  lib/src clean
	rm -f *.o $(PROGS)
