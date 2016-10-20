SHELL = /bin/bash
arch := $(shell uname -p)
pwd := $(shell pwd)

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

buildarg = ""

ifeq ($(arch),ppc64)
  buildarg="--build=ppc64-pc-linux"
endif
ifeq ($(arch),ppc64le)
  buildarg="--build=ppc64le-pc-linux"
endif

libs_dir := $(shell pwd)
$(info LIBSDIR: $(libs_dir))

udp_flag := 1
udp_libs := libcxgb4_udp libcxgb4_sock 
udp_dbg_libs := libcxgb4_udp_dbg libcxgb4_sock_dbg
ifneq ($(filter ppc64 ppc64le,$(arch)),)
  udp_flag := 0
  udp_libs:=
  udp_dbg_libs := 
endif

wdtoe_libs := libwdtoe 
wdtoe_dbg_libs := libwdtoe_dbg

libverbsdir := ${pwd}/libibverbs
libcmdir := ${pwd}/librdmacm
libs_dir := ${pwd}
wdtoedir := $(libs_dir)/libwdtoe
list3 := udp_create_qp.3 udp_poll_cq.3  udp_start_dev.3 udp_dealloc_dev.3 udp_poll_frag.3 udp_stop_dev.3 udp_alloc_dev.3 udp_destroy_qp.3 udp_post_recv.3 udp_attach_mcast.3 udp_detach_mcast.3 udp_post_send.3

libarch := $(shell uname -m | sed 's/i.86/i386/')
ifeq ($(libarch),i386)
   libarchdir := lib
else
   libarchdir := lib64
endif
ifeq ($(DEBIAN),1)
   libarchdir := lib
endif
lib_install_path := /usr/$(libarchdir)

.PHONY: all
all: prep libcxgb4 $(udp_libs) $(udp_dbg_libs)

.PHONY: debug_all
debug_all: $(udp_dbg_libs)

.PHONY: prep
prep:
	@ $(call copydebugslibs)

.PHONY: libcxgb4
libcxgb4: libcxgb4_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4 && $(call logs,iWARP-lib,libcxgb4,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4,Build)

.PHONY: libcxgb4_install
libcxgb4_install: libcxgb4
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4 \
	  install && $(call logs,iWARP-lib,libcxgb4,Install) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4,Install) 

.PHONY: libcxgb4_uninstall
libcxgb4_uninstall: libcxgb4_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4 \
	  uninstall && $(call logs,iWARP-lib,libcxgb4,Uninstall) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4,Uninstall) 

.PHONY: libibverbs
libibverbs:libverbs_prep
	@ $(MAKE) --no-print-directory -C ${libverbsdir}

.PHONY: libibverbs_install
libibverbs_install:libverbs_prep
	@ $(MAKE) --no-print-directory -C ${libverbsdir} install 

.PHONY: libibverbs_uninstall
libibverbs_uninstall:libverbs_prep
	@ $(MAKE) --no-print-directory -C ${libverbsdir} uninstall 


.PHONY: librdmacm
librdmacm:librdmacm_prep
	@ #$(MAKE) --no-print-directory -C ${libcmdir}

.PHONY: librdmacm_install
librdmacm_install:librdmacm_prep
	@ $(MAKE) --no-print-directory -C ${libcmdir} install 

.PHONY: librdmacm_uninstall
librdmacm_uninstall:librdmacm_prep
	@ $(MAKE) --no-print-directory -C ${libcmdir} uninstall 

.PHONY: libcxgb4_prep
libcxgb4_prep:
	@ ( cd $(libs_dir)/libcxgb4 && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) ) || echo ''; 

.PHONY: libcxgb4_udp_prep
libcxgb4_udp_prep:
	@ ( cd $(libs_dir)/libcxgb4_udp && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) ) || echo '';

.PHONY: libcxgb4_udp
libcxgb4_udp: libcxgb4_udp_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4_udp install && $(call logs,iWARP-lib,libcxgb4_udp,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4_udp,Build)

.PHONY: libcxgb4_udp_dbg_prep
libcxgb4_udp_dbg_prep:
	@ ( cd $(libs_dir)/libcxgb4_udp_debug && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) CFLAGS="-g -DDEBUG" && \
	  sed -i 's/src\/libcxgb4_udp.la/src\/libcxgb4_udp_debug.la/' Makefile ; ) || echo ''; 

.PHONY: libcxgb4_udp_dbg
libcxgb4_udp_dbg: libcxgb4_udp_dbg_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4_udp_debug install && $(call logs,iWARP-lib,libcxgb4_udp,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4_udp,Build)

.PHONY: libcxgb4_sock_prep
libcxgb4_sock_prep:
	@ ( cd $(libs_dir)/libcxgb4_sock && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path}  $(buildarg) ) || echo ''; 

.PHONY: libcxgb4_sock
libcxgb4_sock: libcxgb4_sock_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4_sock install && $(call logs,iWARP-lib,libcxgb4_sock,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4_sock,Build)

.PHONY: libcxgb4_sock_dbg_prep
libcxgb4_sock_dbg_prep:
	@ ( cd $(libs_dir)/libcxgb4_sock_debug && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) CFLAGS="-g -DDEBUG" && \
	  sed -i 's/src\/libcxgb4_sock.la/src\/libcxgb4_sock_debug.la/' Makefile && \
	  sed -i 's/lcxgb4_udp/lcxgb4_udp_debug/' Makefile ; ) || echo ''; 

.PHONY: libcxgb4_sock_dbg
libcxgb4_sock_dbg: libcxgb4_sock_dbg_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libcxgb4_sock_debug install && $(call logs,iWARP-lib,libcxgb4_sock,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4_sock,Build)

.PHONY: libwdtoe_prep
libwdtoe_prep:
	@ ( cd $(libs_dir)/libwdtoe && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) ) || echo ''; 

.PHONY: libwdtoe
libwdtoe: libwdtoe_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libwdtoe && $(call logs,iWARP-lib,libwdtoe,Build) \
	  ) || $(call logtemp,iWARP-lib,libcxgb4_sock,Build)

.PHONY: libwdtoe_dbg_prep
libwdtoe_dbg_prep:
	@ ( cd $(libs_dir)/libwdtoe_debug && ./autogen.sh && ./configure \
	              --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} $(buildarg) CFLAGS="-g -DDEBUG" && \
	  sed -i 's/src\/libwdtoe.la/src\/libwdtoe_debug.la/' Makefile; ) || echo ''; 

.PHONY: libwdtoe_dbg
libwdtoe_dbg: libwdtoe_dbg_prep
	@ ($(MAKE) --no-print-directory -C $(libs_dir)/libwdtoe_debug && $(call logs,iWARP-lib,libwdtoe,Build) \
	  ) || $(call logtemp,iWARP-lib,libwdtoe,Build)

.PHONY: libverbs_prep
libverbs_prep:
	@ if [ ! -f $(libs_dir)/libibverbs/Makefile ] ; then \
              ( cd ${libverbsdir} && touch configure aclocal.m4 configure.ac config.h.in Makefile.am Makefile.in config/* ; \
	        ./configure ${buildarg} \
                --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} ) || echo ''; \
	  fi;

.PHONY: librdmacm_prep
librdmacm_prep:
	@ if [ ! -f $(libs_dir)/librdmacm/Makefile ] ; then \
             ( cd ${libcmdir} && touch configure aclocal.m4 configure.ac config.h.in Makefile.am Makefile.in config/*; \
	       ./configure ${buildarg} \
               --prefix=/usr --sysconfdir=/etc --libdir=${lib_install_path} ) || echo ''; \
	  fi;

.PHONY: install
install: libcxgb4 $(udp_libs) 
	@ ( ( test -z "${lib_install_path} || mkdir -p ${lib_install_path}"  ; \
	  test -z "/usr/bin" || mkdir -p -- "/usr/bin" ;\
	  test -z "/usr/include/chelsio" || mkdir -p -- "/usr/include/chelsio" ; \
	  test -z "/usr/man/man3" || mkdir -p -- "/usr/man/man3" ;\
	  test -z "/usr/man/man7" || mkdir -p -- "/usr/man/man7" ;\
	  test -z ${lib_install_path} || mkdir -p -- ${lib_install_path} ;\
	  cd $(libs_dir)/libcxgb4_udp ; \
	  /bin/bash ./libtool --mode=install /usr/bin/install -c  'src/libcxgb4_udp.la' '${lib_install_path}/libcxgb4_udp.la' ; \
	  ./libtool --mode=install /usr/bin/install -c 'examples/udp_test' '/usr/bin/udp_test' ; \
	  cd  $(libs_dir)/libcxgb4_udp ; \
	  /usr/bin/install -c -m 644 'include/chelsio/cxgb4_udp.h' '/usr/include/chelsio/cxgb4_udp.h' ;\
	  /usr/bin/install -c -m 644 'include/chelsio/get_clock.h' '/usr/include/chelsio/get_clock.h' ; \
	  /usr/bin/install -c -m 644 'include/chelsio/queue.h' '/usr/include/chelsio/queue.h' ; \
	  /usr/bin/install -c -m 644 'man/udp_create_qp.3' '/usr/man/man3/udp_create_qp.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_poll_cq.3' '/usr/man/man3/udp_poll_cq.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_start_dev.3' '/usr/man/man3/udp_start_dev.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_dealloc_dev.3' '/usr/man/man3/udp_dealloc_dev.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_poll_frag.3' '/usr/man/man3/udp_poll_frag.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_stop_dev.3' '/usr/man/man3/udp_stop_dev.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_alloc_dev.3' '/usr/man/man3/udp_alloc_dev.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_destroy_qp.3' '/usr/man/man3/udp_destroy_qp.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_post_recv.3' '/usr/man/man3/udp_post_recv.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_attach_mcast.3' '/usr/man/man3/udp_attach_mcast.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_detach_mcast.3' '/usr/man/man3/udp_detach_mcast.3' ;\
	  /usr/bin/install -c -m 644 'man/udp_post_send.3' '/usr/man/man3/udp_post_send.3' ;\
	  /usr/bin/install -c -m 644 'man/cxgb4_udp.7' '/usr/man/man7/cxgb4_udp.7' ; \
	  cd $(libs_dir)/libcxgb4_sock ;\
	  /bin/bash ./libtool --mode=install /usr/bin/install -c  'src/libcxgb4_sock.la' '${lib_install_path}/libcxgb4_sock.la' ;\
	  cd $(libs_dir)/libcxgb4_sock ;\
	  /usr/bin/install -c examples/udp_echo /usr/bin/udp_echo ;\
	  libtool --finish ${lib_install_path}/ ; ldconfig;) && $(call logs,WD-UDP,libcxgb4_sock,Install) \
	  ) || $(call logtemp,WD-UDP,libcxgb4_sock,Install)

.PHONY:install_dbg
install_dbg: $(udp_dbg_libs)
	@ ( ( test -z "${lib_install_path} || mkdir ${lib_install_path} " ; \
          test -z "/usr/bin" || mkdir -p -- "/usr/bin" ;\
          test -z "/usr/include/chelsio" || mkdir -p -- "/usr/include/chelsio" ; \
          test -z "/usr/man/man3" || mkdir -p -- "/usr/man/man3" ;\
          test -z "/usr/man/man7" || mkdir -p -- "/usr/man/man7" ;\
          test -z "${lib_install_path}" || mkdir -p -- "${lib_install_path}" ;\
          cd $(libs_dir)/libcxgb4_udp_debug ; /bin/bash ./libtool --mode=install /usr/bin/install -c  'src/libcxgb4_udp_debug.la' '${lib_install_path}/libcxgb4_udp_debug.la' ; \
          cd  $(libs_dir)/libcxgb4_udp_debug ; \
          cd $(libs_dir)/libcxgb4_sock_debug ;\
          /bin/bash ./libtool --mode=install /usr/bin/install -c  'src/libcxgb4_sock_debug.la' '${lib_install_path}/libcxgb4_sock_debug.la' ;\
          cd $(libs_dir)/libcxgb4_sock_debug ;\
          libtool --finish ${lib_install_path}/ ;ldconfig;) )

.PHONY: uninstall
uninstall: prep
	@ ( for i in $(list3) ; do \
		rm -f /usr/man/man3/$$i ; \
	  done ; \
	  rm -f /usr/man/man7/cxgb4_udp.7 && \
	  rm -f /usr/bin/udp_echo && \
	  rm -f /usr/include/chelsio/cxgb4_udp.h && \
	  rm -f /usr/include/chelsio/get_clock.h && \
	  rm -f /usr/include/chelsio/chelsio/queue.h && \
	  cd $(libs_dir)/libcxgb4_sock ; ./autogen.sh ; ./configure ${buildarg} --prefix=/usr --sysconfdir=/etc \
             --libdir=${lib_install_path} ; ./libtool --mode=uninstall rm -f '${lib_install_path}/libcxgb4_sock.la' && \
	  cd $(libs_dir)/libcxgb4_udp ; ./autogen.sh ; ./configure ${buildarg} --prefix=/usr --sysconfdir=/etc \
             --libdir=${lib_install_path}; ./libtool --mode=uninstall rm -f '${lib_install_path}/libcxgb4_udp.la' && \
	  cd $(libs_dir)/libcxgb4 ; ./autogen.sh ; ./configure ${buildarg} --prefix=/usr --sysconfdir=/etc \
             --libdir=${lib_install_path}; ./libtool --mode=uninstall rm -f '${lib_install_path}/libcxgb4.la' && \
	  cd $(libs_dir)/libcxgb4_sock_debug ; ./autogen.sh ; ./configure ${buildarg} --prefix=/usr --sysconfdir=/etc \
	     --libdir=${lib_install_path} ; ./libtool --mode=uninstall rm -f '${lib_install_path}/libcxgb4_sock_debug.la' && \
	  cd $(libs_dir)/libcxgb4_udp_debug ; ./autogen.sh ;./configure ${buildarg} --prefix=/usr --sysconfdir=/etc \
	     --libdir=${lib_install_path} ; ./libtool --mode=uninstall rm -f '${lib_install_path}/libcxgb4_udp_debug.la' && \
	  ldconfig ; \
	  $(call logs,iWARP-lib,libcxgb4,Uninstall) \
	  if [ $(udp_flag) == 1 ] ; then \
	      $(call logs,WD-UDP,libcxgb4_sock,Uninstall) \
	  fi ; \
	  ) || $(call logtemp,iWARP-lib,libcxgb4,Uninstall) 

define copydebugslibs
  $(shell ${pwd}/../../scripts/cp_debug_libs.sh ${pwd})
endef

define logtemp
echo -e "$1\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log ;
endef

