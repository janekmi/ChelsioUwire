RDMACM_TESTS = rdma_lat rdma_bw

all: ${RDMACM_TESTS} ${MCAST_TESTS} ${TESTS} ${UTILS}

CFLAGS += -Wall -g -D_GNU_SOURCE -O2
BASIC_FILES = get_clock.c
BASIC_HEADERS = get_clock.h
EXTRA_HEADERS = perftest_resources.h perftest_communication.h perftest_parameters.h
MCAST_HEADERS = multicast_resources.h
#The following seems to help GNU make on some platforms
LOADLIBES += -libverbs -lrdmacm
LDFLAGS +=

${MCAST_TESTS}: LOADLIBES += -libumad -lm

${RDMACM_TESTS}: %: %.c ${BASIC_FILES} ${BASIC_HEADERS}
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< ${BASIC_FILES} $(LOADLIBES) $(LDLIBS) -o $@

clean:
	$(foreach fname,${RDMACM_TESTS}, rm -f ${fname})

bw_install:rdma_bw
	install -m 744 rdma_bw /sbin/

lat_install:rdma_lat
	install -m 744 rdma_lat /sbin/
.DELETE_ON_ERROR:
.PHONY: all clean
