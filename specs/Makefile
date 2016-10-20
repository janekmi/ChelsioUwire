SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(info Please use the top-level Makefile to build this driver)
endif

topdir=$(shell pwd)/..
srcdirNw = $(topdir)/build/src/network
srcdirchfcoe = $(topdir)/build/src
FwSrc = $(topdir)/build/src/network/firmware
srcdirTg = $(topdir)/build/src/csiostor_target
srcdirSt = $(topdir)/build/src/scst
srcdir = $(topdir)/build/src/cxgbi
srcdird = $(topdir)/build/src/oiscsi
srcdirs = $(topdir)/build/src/chiscsi
libdirs = $(topdir)/build/libs
toolsdir = $(topdir)/build/tools
srcrdma = $(topdir)/build/src/rdma_block_dev
rpmdir = $(topdir)/rpmbuild
target = $(shell uname -m)
kversion = $(shell uname -r)

udp_libs := libcxgb4_udp libcxgb4_sock libs_dbg
ifneq ($(filter ppc64 ppc64le,$(target)),)
  udp_libs :=
endif

ifeq (${CONF},UNIFIED_WIRE)
    f=$(FwSrc)/*-config.txt
endif
ifeq (${CONF},HIGH_CAPACITY_TOE)
    f=$(FwSrc)/high_capacity_config/*-config.txt
endif
ifeq (${CONF},HIGH_CAPACITY_RDMA)
    f=$(FwSrc)/high_capacity_rdma/*-config.txt
endif
ifeq (${CONF},LOW_LATENCY)
    f=$(FwSrc)/low_latency_config/*-config.txt 
endif
ifeq (${CONF},UDP_OFFLOAD)
    f=$(FwSrc)/udp_so_config/*-config.txt 
endif
ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
    f=$(FwSrc)/edc_only_config/*-config.txt
endif
ifeq ($(CONF),HIGH_CAPACITY_WD)
    f=$(FwSrc)/high_capacity_wd/*-config.txt
endif
ifeq ($(CONF),T5_HASH_FILTER)
    f=$(FwSrc)/hash_filter_config/*-config.txt
endif
ifeq ($(CONF),RDMA_PERFORMANCE)
    f=$(FwSrc)/rdma_perf_config/*-config.txt
endif
ifeq ($(CONF),ISCSI_PERFORMANCE)
    f=$(FwSrc)/iscsi_perf_config/*-config.txt
endif
ifeq ($(CONF),MEMORY_FREE)
    f=$(FwSrc)/memfree_config/*-config.txt
endif

.PHONY: all
all: prep nic toe firmware vnic chiwarp bonding cxgbi oiscsi oiscsiutils \
	chiscsi chutils chiutils

.PHONY: nic_offload
nic_offload: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4" \
	  --define "release 0" \
	  --target $(target) \
	  cxgb4.spec && $(call logs,Network-offload(NIC),cxgb4,rpm) ) || $(call logtemp,Network-offload(NIC),cxgb4,rpm) 

.PHONY: nic_ipv4
nic_ipv4: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4" \
          --define "release 0" \
          --target $(target) \
          cxgb4.spec && $(call logs,Network(NIC_IPV4),cxgb4,rpm) ) || $(call logtemp,Network(NIC_IPV4),cxgb4,rpm)

.PHONY: nic
nic: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4nic" \
          --define "release 0" \
          --target $(target) \
          cxgb4nic.spec && $(call logs,Network(NIC),cxgb4,rpm) ) || $(call logtemp,Network(NIC),cxgb4,rpm) 

.PHONY: toe
toe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4toe" \
	  --define "release 0" \
	  --target $(target) \
	  cxgb4toe.spec && $(call logs,Network-offload(TOE),t4_tom,rpm) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	    $(call logs,Udp_offload,t4_tom,rpm) \
	  fi ; \
	  if [ $(ipv6_enable) -eq 1 ] ; then \
	   $(call logs,Ipv6_offload,t4_tom,rpm) \
	  fi;\
	  ) || $(call logtemp,Network-offload(TOE),t4_tom,rpm) 

.PHONY: wdtoe
wdtoe: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4wdtoe" \
          --define "release 0" \
          --target $(target) \
          cxgb4wdtoe.spec && $(call logs,WD-TOE,t4_tom,rpm) ) || $(call logtemp,WD-TOE,t4_tom,rpm) 

.PHONY: udp_offload
udp_offload: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4toe" \
          --define "release 0" \
          --target $(target) \
          cxgb4toe.spec && $(call logs,Network(UDP-Offload),t4_tom,rpm) ) || $(call logtemp,Network(UDP-Offload),t4_tom,rpm) 


.PHONY: toe_ipv4
toe_ipv4: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4toe-ipv4" \
	  --define "release 0" \
	  --target $(target) \
	  cxgb4toe.spec && $(call logs,Network-offload(TOE_IPV4),t4_tom,rpm) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
             $(call logs,Udp_offload,t4_tom,rpm) \
	  fi ; \
	  ) || $(call logtemp,Network-offload(TOE),t4_tom,rpm) 

.PHONY: bypass
bypass: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name bypass" \
	  --define "release 0" \
	  --target $(target) \
	  bypass.spec && $(call logs,Network-Offload(Bypass),cxgb4,rpm) ) || $(call logtemp,Network-Offload(Bypass),cxgb4,rpm) 

.PHONY: ipv6
ipv6: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4ipv6" \
          --define "release 0" \
          --target $(target) \
          cxgb4ipv6.spec && $(call logs,IPv6-offload,ipv6,rpm) ) || $(call logtemp,IPv6-offload,ipv6,rpm) 

.PHONY: toe_ipv6
toe_ipv6: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4ipv6" \
          --define "release 0" \
          --target $(target) \
          cxgb4toe.spec && $(call logs,IPv6-offload,ipv6,rpm) ) || $(call logtemp,IPv6-offload,ipv6,rpm) 

.PHONY: firmware
firmware: prep
	 @ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "conffile $(f)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-series4-firmware" \
	  --define "release 0" \
	  --target $(target) \
	  firmware.spec && $(call logs,Firmware,t4fw-X.Y.Z.bin,rpm) ) || $(call logtemp,Firmware,t4fw-X.Y.Z.bin,rpm) 

.PHONY: chiwarp
chiwarp: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiwarp" \
	  --define "release 0" \
	  --target $(target) \
	  chiwarp.spec && $(call logs,RDMA(iWARP),iw_cxgb4,rpm) ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,rpm) 

.PHONY: sniffer
sniffer: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(toolsdir)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name sniffer" \
          --define "release 0" \
          --target $(target) \
          sniffer.spec && $(call logs,Sniffer,wd_tcpdump,rpm) ) || $(call logtemp,Sniffer,wd_tcpdump,rpm) 

.PHONY: bonding
bonding: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name bonding" \
	  --define "release 0" \
	  --target $(target) \
	  bonding.spec && $(call logs,Bonding-offload,bonding,rpm) ) || $(call logtemp,Bonding-offload,bonding,rpm) 

.PHONY: fcoe
fcoe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name csiostor-initiator" \
	  --define "release 0" \
	  --target $(target) \
	  csiostor.spec && $(call logs,FCoE(full-offload-initiator),csiostor,rpm) ) || ( $(call logtemp,FCoE(full-offload-initiator),csiostor,rpm))

.PHONY: chfcoe
chfcoe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirchfcoe)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chfcoe" \
	  --define "release 0" \
	  --target $(target) \
	  chfcoe.spec && $(call logs,chfcoe(PDU-Offload-Target),chfcoe,rpm) ) || ( $(call logtemp,chfcoe(PDU-Offload-Target),chfcoe,rpm))

.PHONY: fcoe_target
fcoe_target: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirTg)" \
	  --define "srcdirSt $(srcdirSt)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name csiostor-target" \
	  --define "release 0" \
	  --target $(target) \
	  csiostor-scst.spec && $(call logs,FCoE(full-offload-target),csioscst,rpm) ) || $(call logtemp,FCoE(full-offload-target),csioscst,rpm) 

.PHONY: cxgbi
cxgbi: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdir)"  \
	  --define "osrcdir $(srcdird)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4i" \
	  --define "release 0" \
	  --target $(target) \
	  cxgbi.spec && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm) \
	  ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm) 

.PHONY: vnic
vnic: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4vf" \
	  --define "release 0" \
	  --target $(target) \
	  cxgb4vf.spec && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,rpm) ) || $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,rpm) 

.PHONY: oiscsiutils
oiscsiutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdird)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name oiscsi-utils" \
	  --define "release 0" \
	  --target $(target) \
	  oiscsi-data.spec && $(call logs,iSCSI(user_utilities),iscsi*,rpm) \
	  ) || $(call logtemp,iSCSI(user_utilities),iscsi*,rpm) 

.PHONY: chiscsi
chiscsi: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiscsi" \
	  --define "release 0" \
	  --target $(target) \
	  chiscsi.spec && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,rpm) \
	  ) || ( $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,rpm) \
	   $(call logtemp,iSCSI(target_user_util),iscsictl,rpm))

.PHONY: chutils
chutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(toolsdir)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-utils" \
	  --define "release 0" \
	  --target $(target) \
	  chelsio-utils.spec && $(call logs,Chelsio-utils(tools),cxgbtool,rpm) \
	  ) || $(call logtemp,Chelsio-utils(tools),cxgbtool,rpm) 

.PHONY: bypassutils
bypassutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(toolsdir)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-bypass-utils" \
	  --define "release 0" \
	  --target $(target) \
	  bypass-utils.spec && $(call logs,Bypass_tools,ba_*,rpm) \
	  ) || $(call logtemp,Bypass_tools,ba_*,rpm) 

.PHONY: chiutils
chiutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiscsi-utils" \
	  --define "release 0" \
	  --define "arch $(target)" \
	  --target $(target) \
	  chiscsi-data.spec && $(call logs,iSCSI(target_user_util),iscsictl,rpm) \
	  ) || $(call logtemp,iSCSI(target_user_util),iscsictl,rpm) 

.PHONY: rdma_block
rdma_block: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcrdma)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name rdma-block-device" \
	  --define "release 0" \
	  --define "arch $(target)" \
	  --target $(target) \
	  rdma_block.spec && $(call logs,RDMA-Block-Device,rbd,rpm) \
	  ) || $(call logtemp,RDMA-Block-Device,rbd,rpm) 

.PHONY: libs
libs: libcxgb4 $(udp_libs)

.PHONY: libs_dbg
libs_dbg: libcxgb4_udp_dbg libcxgb4_sock_dbg

.PHONY: libcxgb4
libcxgb4: prep
	@  $(call checklibibverbs,,rpm,RDMA(iWARP-Lib),libcxgb4,${vers})
	@  rm -rf libcxgb4-$(vers) libcxgb4-$(vers).tar.gz

.PHONY: libibverbs
libibverbs: prep
	@  $(call checklibibverbs,,rpm,RDMA(iWARP-Lib),libibverbs,1.1.8)
	@  rm -rf libibverbs-$(vers) libibverbs-1.1.8*

.PHONY: librdmacm
librdmacm: prep
	@  $(call checklibibverbs,,rpm,RDMA(iWARP-Lib),librdmacm,1.0.21)
	@  rm -rf librdmacm-$(vers) librdmacm-1.0.21*

.PHONY: libcxgb4_udp
libcxgb4_udp: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(libdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name libcxgb4_udp" \
	  --define "release 0" \
	  --target $(target) \
	  libcxgb4_udp.spec & $(call logs,WD-UDP-Libraries,libcxgb4_udp,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_udp,rpm)

.PHONY:wdtoe_libs
wdtoe_libs:prep wdtoe_libs_debug
	rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libwdtoe" \
          --define "release 0" \
          --target $(target) \
          libwdtoe.spec

.PHONY:wdtoe_libs_debug
wdtoe_libs_debug:prep
	rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libwdtoe_dbg" \
          --define "release 0" \
          --target $(target) \
          libwdtoe_dbg.spec

.PHONY: libcxgb4_sock
libcxgb4_sock: prep libcxgb4_udp
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(libdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name libcxgb4_sock" \
	  --define "release 0" \
	  --target $(target) \
	  libcxgb4_sock.spec && $(call logs,WD-UDP-Libraries,libcxgb4_sock,rpm) \
	  ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_sock,rpm) 

.PHONY: libcxgb4_udp_dbg
libcxgb4_udp_dbg: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libcxgb4_udp_debug" \
          --define "release 0" \
          --target $(target) \
          libcxgb4_udp_dbg.spec && $(call logs,WD-UDP-Libraries,libcxgb4_udp_dbg,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_udp_dbg,rpm)

.PHONY: libcxgb4_sock_dbg
libcxgb4_sock_dbg: prep libcxgb4_udp_dbg
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libcxgb4_sock_debug" \
          --define "release 0" \
          --target $(target) \
          libcxgb4_sock_dbg.spec && $(call logs,WD-UDP-Libraries,libcxgb4_sock_dbg,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_sock_dbg,rpm)

.PHONY: prep
prep:
	@ package=$(pkgname)-$(pkgvers);\
	  /bin/mkdir -p $(rpmdir)/BUILD/$$package;\
	  /bin/mkdir -p $(rpmdir)/SOURCES ;\
	  /bin/mkdir -p $(rpmdir)/RPMS/$(target);

define logtemp
echo -e "$1\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log  ;
endef

define checklibibverbs
        if [ $(shell uname -p) == "x86_64" ] ; then \
               cp -rpf $(libdirs)/$4 $(libdirs)/$4-$5 ; \
               cp -rpf $(libdirs)/$4-$5 . ; \
               tar cfz $4-$5.tar.gz $4-$5 ; \
               cp $4-$5.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(libdirs)/$4" \
               --define "kversion $(kversion)" \
               --define "version $5" \
               --define "name $4" \
               --define "release 0" \
               --target $(target) \
               $(libdirs)/$4/$4.spec && $(call logs,iWARP-lib,$4,rpm) \
               ) || $(call logtemp,iWARP-lib,$4,rpm) \
        else \
               cp -rvf $(libdirs)/$4 $(libdirs)/$4-$5; \
               cp -rvf $(libdirs)/$4-$5 . ; \
               tar cvfz $4-$5.tar.gz $4-$5 ; \
               cp $4-$5.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(libdirs)/$4" \
               --define "kversion $(kversion)" \
               --define "version $5" \
               --define "name $4" \
               --define "release 0" \
               --target $(target) \
               $(libdirs)/$4/$4.spec && $(call logs,iWARP-lib,$4,rpm) \
               ) || $(call logtemp,iWARP-lib,$4,rpm) \
        fi ;
endef
