SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(info Please use the top-level Makefile to build this driver)
endif

VERSION=$(vers)
RELEASE=0
DPKGDEB=$(shell which dpkg-deb)
INSTALL=$(shell which install)
uname=$(shell uname -r)
PWD=$(shell pwd)
BUILDDIR=$(PWD)/../build/src
DEST_DIR=/lib/modules/$(uname)/updates
NET_DEST_DIR=$(DEST_DIR)/kernel/drivers/net
DEBDIR=${PWD}/debian
DEBBUILD_DIR=${DEBDIR}/DEBIAN
POSTINT=${DEBBUILD_DIR}/postinst
FW_DIR=/lib/firmware/cxgb4/
FIND=$(shell which find)
arch=$(shell uname -m)
debinaries=${PWD}/debinaries
#arch=amd64
lib_install_path = /usr/lib
topdir=$(shell pwd)/..
kversion = $(shell uname -r)
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

export kdist

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

define generate_control
	$(shell ${PWD}/generate_control.sh $(VERSION) $(1) $(2)) 
endef

.PHONY: prep nic nic_offload toe wdtoe udp_offload chiwarp firmware sniffer bonding fcoe cxgbi vnic chiscsi chutils bypassutils distclean
nic: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep  ; \
	  fi ;
	@ ( mkdir -p $(DEBDIR)/$(NET_DEST_DIR)/cxgb4 ; $(INSTALL) -D -v $(BUILDDIR)/network/cxgb4/cxgb4.ko ${DEBDIR}/$(NET_DEST_DIR)/cxgb4/ ;\
	  cp -rf ${PWD}/controls/nic $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4nic-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Network(NIC),cxgb4,deb) ) || $(call logtemp,Network(NIC),cxgb4,deb)

nic_offload: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p debian/$(NET_DEST_DIR)/cxgb4 ; $(INSTALL) -D -v $(BUILDDIR)/network/cxgb4/cxgb4.ko debian/${NET_DEST_DIR}/cxgb4/cxgb4.ko ; \
	  cp -rf ${PWD}/controls/nic_offload $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Network-offload(NIC),cxgb4,deb) ) || $(call logtemp,Network-offload(NIC),cxgb4,deb)

toe: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  cp -rf ${PWD}/controls/toe $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/toecore/toecore.ko debian/$(NET_DEST_DIR)/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/t4_tom/t4_tom.ko debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4toe-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Network-offload(TOE),t4_tom,deb) \
          if [ $(is_udp_offload) -eq 1 ] ; then \
            $(call logs,Udp_offload,t4_tom,deb) \
          fi ; \
          if [ $(ipv6_enable) -eq 1 ] ; then \
           $(call logs,Ipv6_offload,t4_tom,deb) \
          fi;\
          ) || $(call logtemp,Network-offload(TOE),t4_tom,deb)

wdtoe: prep
	@ if [ ! -d debian ] ; then \
		make --no-print-directory prep ; \
 	  fi ;
	@ ( mkdir -p debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  cp -rf ${PWD}/controls/wdtoe $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/cxgb4/cxgb4.ko debian/${NET_DEST_DIR}/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/toecore/toecore.ko debian/$(NET_DEST_DIR)/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/t4_tom/t4_tom.ko debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4wdtoe-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,WD-TOE,t4_tom,deb) ) || $(call logtemp,WD-TOE,t4_tom,deb)

udp_offload: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  cp -rf ${PWD}/controls/udp_offload $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/toecore/toecore.ko debian/$(NET_DEST_DIR)/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/t4_tom/t4_tom.ko debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4toe-udpso-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Network(UDP-Offload),t4_tom,deb) ) || $(call logtemp,Network(UDP-Offload),t4_tom,deb)

bypass: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p debian/$(NET_DEST_DIR)/offload/t4_tom debian/$(DEST_DIR)/drivers/infiniband/hw/cxgb4; \
	  cp -rf ${PWD}/controls/bypass $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/cxgb4/cxgb4.ko debian/${NET_DEST_DIR}/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/toecore/toecore.ko debian/$(NET_DEST_DIR)/offload/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/t4_tom/t4_tom.ko debian/$(NET_DEST_DIR)/offload/t4_tom/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/bypass-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR}  && $(call logs,Network(Bypass),cxgb4,deb) ) || $(call logtemp,Network(Bypass),cxgb4,deb)

firmware: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p debian/$(FW_DIR) ; \
	  install -D -v -m 644 $(f) debian/$(FW_DIR) ; \
	  install -D -v -m 644 $(srcdirNw)/firmware/*.bin debian/$(FW_DIR) ; \
	  install -D -v -m 644 $(srcdirNw)/firmware/*.cld debian/$(FW_DIR) ; \
	  install -D -v -m 644 ${toolsdir}/chelsio_adapter_config_v4/vpds/*.bin debian/$(FW_DIR) ; \
	  cp -rf ${PWD}/controls/firmware $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/chelsio-series4-firmware-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Firmware,t4fw-X.Y.Z.bin,deb) ) || $(call logtemp,Firmware,t4fw-X.Y.Z.bin,deb)

chiwarp: prep
	@ if [ ! -d debian ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p debian/$(DEST_DIR)/drivers/infiniband/hw/iw_cxgb4; \
	  cp -rf ${PWD}/controls/chiwarp $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/iw_cxgb4/iw_cxgb4.ko debian/$(DEST_DIR)/drivers/infiniband/hw/iw_cxgb4/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/chiwarp-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,RDMA(iWARP),iw_cxgb4,deb) ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,deb)

sniffer: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p debian/sbin; \
          $(INSTALL) -D -v -m 755 ${toolsdir}/t4_sniffer/tcpdump-4.1.1/wd_tcpdump ${DEBDIR}/sbin/ ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/t4_sniffer/tcpdump-4.1.1/wd_tcpdump_trace ${DEBDIR}/sbin/ ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/t4_sniffer/sniffer_rdma_filter/sniffer  ${DEBDIR}/sbin/wd_sniffer ; \
	  cp -rf ${PWD}/controls/sniffer $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/sniffer-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Sniffer,wd_tcpdump,deb) ) || $(call logtemp,Sniffer,wd_tcpdump,deb)

bonding: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p debian/$(NET_DEST_DIR)/bonding/ ; \
	  cp -rf ${PWD}/controls/bonding $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/bonding/bonding.ko debian/$(NET_DEST_DIR)/bonding/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/bonding-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,Bonding-offload,bonding,deb) ) || $(call logtemp,Bonding-offload,bonding,deb)

fcoe: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p $(DEBDIR)/$(DEST_DIR)/drivers/scsi/csiostor/ $(DEBDIR)/lib/udev $(DEBDIR)/lib/udev/rules.d $(DEBDIR)/etc/modprobe.d ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/csiostor/csiostor.ko $(DEBDIR)/$(DEST_DIR)/drivers/scsi/csiostor/ ; \
	  $(INSTALL) -D -v $(BUILDDIR)/network/csiostor/udev/path_chelsio_id $(DEBDIR)/lib/udev/ ; \
	  $(INSTALL) -D -v -m 644 $(BUILDDIR)/network/csiostor/udev/30-chelsio-storage.rules $(DEBDIR)/lib/udev/rules.d/ ; \
	  $(INSTALL) -D -v -m 644 $(BUILDDIR)/network/csiostor/csiostor.conf $(DEBDIR)/etc/modprobe.d/ ; \
	  cp -rf ${PWD}/controls/fcoe $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/csiostor-initiator-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,FCoE(full-offload-initiator),csiostor,deb) ) || ( $(call logtemp,FCoE(full-offload-initiator),csiostor,deb))

chfcoe: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p $(DEBDIR)/lib/modules/$(uname)/extra $(DEBDIR)/etc/modprobe.d/ $(DEBDIR)/etc/chelsio-fcoe $(DEBDIR)/sbin $(DEBDIR)/etc/init.d ; \
	  cp -rf ${PWD}/controls/chfcoe $(DEBBUILD_DIR) ; \
	  $(INSTALL) -D -v $(srcdirchfcoe)/chfcoe/src/chfcoe.ko $(DEBDIR)/lib/modules/$(uname)/extra/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirchfcoe)/chfcoe/config/chfcoe.conf $(DEBDIR)/etc/modprobe.d/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirchfcoe)/chfcoe/config/chfcoe_scst.conf $(DEBDIR)/etc/chelsio-fcoe/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirchfcoe)/chfcoe/tools/chinfotool64 $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirchfcoe)/chfcoe/tools/chfcoe_perftune.sh $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirchfcoe)/chfcoe/tools/chfcoe $(DEBDIR)/etc/init.d/ ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/chfcoe-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,chfcoe(PDU-Offload-Target),chfcoe,deb) ) || ( $(call logtemp,chfcoe(PDU-Offload-Target),chfcoe,deb))

cxgbi: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/cxgbi/ $(DEBDIR)/sbin $(DEBDIR)/etc/iscsi/ifaces/ ; \
	  $(INSTALL) -D -v $(srcdir)/libcxgbi/libcxgbi.ko $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/cxgbi/ ; \
	  $(INSTALL) -D -v $(srcdir)/cxgb4i/cxgb4i.ko $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/cxgbi/ ; \
	  $(INSTALL) -D -v $(srcdird)/usr/iscsid $(DEBDIR)/sbin/iscsid2 ; \
	  $(INSTALL) -D -v $(srcdird)/usr/iscsiadm $(DEBDIR)/sbin/iscsiadm2 ; \
	  $(INSTALL) -D -v $(srcdird)/utils/iscsi_discovery $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v $(srcdird)/utils/iscsi-iname $(DEBDIR)/sbin/iscsi-iname2 ; \
	  $(INSTALL) -D -v $(srcdird)/etc/iface.example $(DEBDIR)/etc/iscsi/ifaces/ ; \
	  $(INSTALL) -D -v $(srcdird)/etc/iscsid.conf $(DEBDIR)/etc/iscsi/iscsid.conf.2 ; \
	  cp -rf ${PWD}/controls/cxgbi $(DEBBUILD_DIR) ; \
	  $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/cxgb4i-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,deb) \
          ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,deb)

vnic: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ (mkdir -p $(DEBDIR)/$(NET_DEST_DIR)/cxgb4vf ; $(INSTALL) -D -v $(BUILDDIR)/network/cxgb4vf/cxgb4vf.ko ${DEBDIR}/$(NET_DEST_DIR)/cxgb4vf/ ; \
          cp -rf ${PWD}/controls/vnic $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/cxgb4vf-$(VERSION)-$(RELEASE)-$(arch).deb ; \
          rm -rf ${DEBDIR} && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,deb) ) || $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,deb)
	 
chiscsi: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ; #Need to add chiscsi_t3 support
	@ ( mkdir -p $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/chiscsi $(DEBDIR)/etc/chelsio-iscsi $(DEBDIR)/etc/bash_completion.d $(DEBDIR)/etc/init.d $(DEBDIR)/etc/sysconfig $(DEBDIR)/sbin $(DEBDIR)/usr/share/man/man8; \
	  $(INSTALL) -D -v $(srcdirs)/base/chiscsi_base.ko $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/chiscsi/ ; \
	  $(INSTALL) -D -v $(srcdirs)/t4/chiscsi_t4.ko $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/chiscsi/ ; \
	  if [ -f $(srcdirs)/t3/chiscsi_t3.ko ] ; then \
	  	$(INSTALL) -D -v $(srcdirs)/t3/chiscsi_t3.ko $(DEBDIR)/$(DEST_DIR)/kernel/drivers/scsi/chiscsi/ ; \
	  fi ; \
	  $(INSTALL) -D -v -m 755 $(srcdirs)/user/iscsictl $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirs)/user/chisns $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/user/bash/iscsictl $(DEBDIR)/etc/bash_completion.d/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/user/bash/chisns $(DEBDIR)/etc/bash_completion.d/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirs)/tools/chiscsi_set_affinity.sh $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/example/chiscsi.conf $(DEBDIR)/etc/chelsio-iscsi/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/example/chiscsi.conf $(DEBDIR)/etc/sysconfig/ ; \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/example/initd/chiscsi $(DEBDIR)/etc/sysconfig/ ; \
	  $(INSTALL) -D -v -m 755 $(srcdirs)/example/initd/chelsio-target $(DEBDIR)/etc/init.d/ ;  \
	  $(INSTALL) -D -v -m 644 $(srcdirs)/docs/iscsictl.8.gz $(DEBDIR)/usr/share/man/man8/ ; \
	  if [ -f $(srcdirs)/user/chinfotool64 ] || [ -f $(srcdirs)/user/chinfotool32 ] ; then \
	  if [ $(arch) == 'x86_64' ] ; then \
		$(INSTALL) -D -v $(srcdirs)/user/chinfotool64 $(DEBDIR)/sbin/ ; \
	  else \
	  	$(INSTALL) -D -v $(srcdirs)/user/chinfotool32 $(DEBDIR)/sbin/ ; \
	  fi ; \
	  fi ; \
	  cp -rf ${PWD}/controls/chiscsi $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/chiscsi-$(VERSION)-$(RELEASE)-$(arch).deb ; \
          rm -rf ${DEBDIR} && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,deb) \
          ) || ( $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,deb) \
           $(call logtemp,iSCSI(target_user_util),iscsictl,deb))

chutils: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p  $(DEBDIR)/sbin $(DEBDIR)/usr/share/man/man8 ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/cxgbtool/cxgbtool $(DEBDIR)/sbin/ ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/cudbg/app/cudbg_app $(DEBDIR)/sbin/ ; \
	  if [ -f ${toolsdir}/cop/cop ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/cop/cop $(DEBDIR)/sbin/ ; \
	  fi ; \
	  $(INSTALL) -D -v -m 644 ${toolsdir}/cxgbtool/cxgbtool.8 $(DEBDIR)/usr/share/man/man8/ ; \
	  $(INSTALL) -D -v -m 644 ${toolsdir}/cop/cop.8	$(DEBDIR)/usr/share/man/man8/ ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/t4_perftune.sh $(DEBDIR)/sbin/t4_perftune.sh ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/t4_latencytune.sh $(DEBDIR)/sbin/t4_latencytune.sh ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/wdload $(DEBDIR)/sbin/wdload ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/wdunload $(DEBDIR)/sbin/wdunload ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/chstatus $(DEBDIR)/sbin/chstatus ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/chsetup $(DEBDIR)/sbin/chsetup ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/chdebug $(DEBDIR)/sbin/chdebug ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/t4-forward.sh $(DEBDIR)/sbin/t4-forward.sh ; \
	  $(INSTALL) -D -v -m 755 ${toolsdir}/uname_r $(DEBDIR)/sbin/uname_r ; \
	  if [ -f ${toolsdir}/benchmarks/netperf/src/netperf ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/netperf/src/netperf $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/netperf/src/netserver ] ; then \
                $(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/netperf/src/netserver $(DEBDIR)/sbin/ ; \
          fi ; \
	  if [ -f ${toolsdir}/benchmarks/sockperf/src/sockperf ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/sockperf/src/sockperf $(DEBDIR)/sbin/ ; \
          fi ; \
	  if [ -f ${toolsdir}/benchmarks/sockperf-lite/src/sockperf ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/sockperf-lite/src/sockperf $(DEBDIR)/sbin/sockperf-lite ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/hpcbench/tcp/tcpserver ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/hpcbench/tcp/tcpserver $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/hpcbench/tcp/tcptest ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/hpcbench/tcp/tcptest $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/hpcbench/udp/udptest ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/hpcbench/udp/udptest $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/hpcbench/udp/udpserver ] ; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/hpcbench/udp/udpserver $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/iperf/src/iperf ]; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/iperf/src/iperf $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/benchmarks/netpipe/NPtcp ]; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/benchmarks/netpipe/NPtcp $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/chelsio_adapter_config_v4/bin/chelsio_adapter_config ]; then  \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/chelsio_adapter_config_v4/bin/chelsio_adapter_config $(DEBDIR)/sbin/ ; \
	  fi ; \
	  if [ -f ${toolsdir}/chelsio_adapter_config_v4/bin/t5seeprom ]; then \
	  	$(INSTALL) -D -v -m 755 ${toolsdir}/chelsio_adapter_config_v4/bin/t5seeprom $(DEBDIR)/sbin/ ; \
	  fi ; \
	  cp -rf ${PWD}/controls/chutils $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/chelsio-utils-$(VERSION)-$(RELEASE)-$(arch).deb ; \
          rm -rf ${DEBDIR} && $(call logs,Chelsio-utils(tools),cxgbtool,deb) \
          ) || $(call logtemp,Chelsio-utils(tools),cxgbtool,deb)

bypassutils: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ ( mkdir -p $(DEBDIR)/sbin $(DEBDIR)/etc/init.d ; \
	  ${INSTALL} -D -m 755 ${toolsdir}/ba_server/build/t4/ba_server $(DEBDIR)/sbin/ba_server ; \
    	  ${INSTALL} -D -m 755 ${toolsdir}/ba_server/build/t4/ba_client  ${DEBDIR}/sbin/ba_client ; \
	  ${INSTALL} -D -m 755 ${toolsdir}/ba_server/build/ba-rc  ${DEBDIR}/etc/init.d/bad ; \
          cp -rf ${PWD}/controls/bypass-utils $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/chelsio-bypass-utils-$(VERSION)-$(RELEASE)-$(arch).deb ; \
          rm -rf ${DEBDIR} && $(call logs,Bypass_tools,ba_*,deb) \
          ) || $(call logtemp,Bypass_tools,ba_*,deb) 
        
libs: libcxgb4_devel libcxgb4_udp libcxgb4_sock libs_dbg

libs_dbg: libcxgb4_udp_dbg libcxgb4_sock_dbg

libcxgb4: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ;
	@ mkdir -p $(DEBDIR)/etc/libibverbs.d/ $(DEBDIR)/$(lib_install_path)/ $(DEBDIR)/usr/share/doc/libcxgb4-${VERSION} ; \
	  (($(MAKE) --no-print-directory -C $(libdirs) libcxgb4 ) && \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/src/.libs/libcxgb4-rdmav2.so $(DEBDIR)/$(lib_install_path)/ ; \
	  ( cd $(DEBDIR)/$(lib_install_path)/ ; ln -s libcxgb4-rdmav2.so libcxgb4.so ); \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/cxgb4.driver $(DEBDIR)/etc/libibverbs.d/ ; \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/AUTHORS $(DEBDIR)/usr/share/doc/libcxgb4-${VERSION}/AUTHORS ; \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/COPYING $(DEBDIR)/usr/share/doc/libcxgb4-${VERSION}/COPYING ; \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/ChangeLog $(DEBDIR)/usr/share/doc/libcxgb4-${VERSION}/ChangeLog ; \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/README $(DEBDIR)/usr/share/doc/libcxgb4-${VERSION}/README ; ) ; \
	  cp -rf ${PWD}/controls/libcxgb4 $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/libcxgb4-$(VERSION)-$(RELEASE)-$(arch).deb ; \
          rm -rf ${DEBDIR} ; 

libcxgb4_devel: libcxgb4 prep
	@ if [ ! -d ${DEBDIR} ] ; then \
		make --no-print-directory prep ; \
	  fi ;
	@ ( mkdir -p $(DEBDIR)/$(lib_install_path)/ ; \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4/src/.libs/libcxgb4.a $(DEBDIR)/$(lib_install_path)/ ; \
	  cp -rf ${PWD}/controls/libcxgb4-devel $(DEBBUILD_DIR) ; \
          $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libcxgb4-devel-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iWARP-lib,$@,deb) \
          ) || $(call logtemp,iWARP-lib,$@,deb)

libcxgb4_udp: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ; 
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path)/ $(DEBDIR)/usr/bin $(DEBDIR)/usr/include/chelsio $(DEBDIR)/usr/share/man/man3 $(DEBDIR)/usr/share/man/man7 ) \
	  $(info $(shell for f in $$(ls $(libdirs)/libcxgb4_udp/include/chelsio/*) ;  do install -D -v "$$f" $(DEBDIR)/usr/include/chelsio/ ; echo ; done ) ) \
	  $(info $(shell find $(libdirs)/libcxgb4_udp/ -name libcxgb4_udp\* -type f -exec install {} $(DEBDIR)/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find $(DEBDIR)/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libcxgb4_udp/examples/.libs/udp_test ${DEBDIR}/usr/bin/ ; \
	  cp -rf ${PWD}/controls/libcxgb4_udp $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
          mv debian.deb ${debinaries}/libcxgb4_udp-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iWARP-lib,$@,rpm) \
	   ) || $(call logtemp,iWARP-lib,$@,rpm)

libcxgb4_sock: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ; 
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path) $(DEBDIR)/usr/bin ) \
	  $(info $(shell find ${libdirs}/libcxgb4_sock/ -name libcxgb4_sock\* -type f -exec install {} ${DEBDIR}/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find ${DEBDIR}/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  cp -rf ${PWD}/controls/libcxgb4_sock $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libcxgb4_sock-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iWARP-lib,$@,rpm) \
          ) || $(call logtemp,iWARP-lib,$@,rpm)

libcxgb4_udp_dbg: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
		make --no-print-directory prep ; \
	  fi ; 
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path)/ ) \
	  $(info $(shell find $(libdirs)/libcxgb4_udp_debug/ -name libcxgb4_udp_debug\* -type f -exec install {} $(DEBDIR)/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find $(DEBDIR)/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  cp -rf ${PWD}/controls/libcxgb4_udp_dbg $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libcxgb4_udp_debug-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iWARP-lib,$@,rpm) \
          ) || $(call logtemp,iWARP-lib,$@,rpm)

libcxgb4_sock_dbg: prep
	@ if [ ! -d ${DEBDIR} ] ; then \
                make --no-print-directory prep ; \
          fi ; 
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path)/ $(DEBDIR)/usr/bin ) \
	  $(info $(shell find ${libdirs}/libcxgb4_sock_debug/ -name libcxgb4_sock_debug\* -type f -exec install {} ${DEBDIR}/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find ${DEBDIR}/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  cp -rf ${PWD}/controls/libcxgb4_sock_dbg $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libcxgb4_sock_debug-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,iWARP-lib,$@,rpm) \
          ) || $(call logtemp,iWARP-lib,$@,rpm)

wdtoe_libs:prep wdtoe_libs_debug
	@ if [ ! -d ${DEBDIR} ] ; then \
		make --no-print-directory prep ; \
	  fi ;
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path)/ $(DEBDIR)/etc ) \
	  ${INSTALL} -D -v -m 755 $(libdirs)/libwdtoe/examples/wdtoe.conf $(DEBDIR)/etc/ ; \
	  $(info $(shell find $(libdirs)/libwdtoe/ -name libwdtoe\* -type f -exec install {} $(DEBDIR)/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find $(DEBDIR)/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  cp -rf ${PWD}/controls/libwdtoe $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libwdtoe-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,libwdtoe,$@,rpm) \
          ) || $(call logtemp,libwdtoe,$@,rpm)

wdtoe_libs_debug:prep
	@ if [ ! -d ${DEBDIR} ] ; then \
		make --no-print-directory prep ; \
	  fi ;
	@ $(shell mkdir -p $(DEBDIR)/$(lib_install_path)/ $(DEBDIR)/etc ) \
	  $(info $(shell find $(libdirs)/libwdtoe_debug/ -name libwdtoe_debug\* -type f -exec install {} $(DEBDIR)/$(lib_install_path)/ \;; ) ) \
	  $(info $(shell find $(DEBDIR)/$(lib_install_path)/ -name *.lai -type f -exec rm {} \; ) ) \
	  cp -rf ${PWD}/controls/libwdtoe_dbg $(DEBBUILD_DIR) ; \
	  ( $(DPKGDEB) --build debian ; \
	  mv debian.deb ${debinaries}/libwdtoe_dbg-$(VERSION)-$(RELEASE)-$(arch).deb ; \
	  rm -rf ${DEBDIR} && $(call logs,libwdtoe-dbg,$@,rpm) \
          ) || $(call logtemp,libwdtoe-dbg,$@,rpm)

clean:
	@ rm -rf debian > /dev/null 2>&1 ;

distclean:
	@ rm -rf debian ${debinaries} > /dev/null 2>&1 ;

prep:
	@ if [ ! -d ${debinaries} ] ; then \
	  	/bin/mkdir -p ${debinaries} ; \
	  fi ; \
	  if [ ! -d ${DEBDIR} ] ; then \
                /bin/mkdir -p ${DEBDIR} ; \
          fi ; 

define logtemp
echo -e "$1\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log  ;
endef

