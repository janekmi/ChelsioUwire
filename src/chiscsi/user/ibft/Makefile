PTFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wstrict-prototypes
CFLAGS += $(OPTFLAGS) $(WARNFLAGS)
PROGRAMS = chibft

all: $(PROGRAMS)

chibft: ibft.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)


