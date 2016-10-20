SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

oiscsiSrc2= $(shell pwd)/oiscsi-v872
oiscsiSrc3= $(shell pwd)/open-iscsi-2.0-873
oiscsiSrc= $(shell pwd)/oiscsi
fcoeTgtSrc= $(shell pwd)/csiostor_target
cxgb4Src = $(shell pwd)/network
chiscsiSrc = $(shell pwd)/chiscsi
chfcoeSrc = $(shell pwd)/chfcoe/linux
scstSrc = $(shell pwd)/scst
csioSrc = $(shell pwd)/network/csiostor/include
firmwarePath = $(shell pwd)/network/firmware
rdmablkSrc= $(shell pwd)/rdma_block_dev
uname = ${UNAME_R}
src = $(shell pwd)
#disable_mafo = 1
#export disable_mafo
export enable_dcb
export DEBUG
export po_fcoe
define enable_tgt 
   override $(1) = 1
endef
define disable_tgt 
   override $(1) = 0
endef
ifdef ipv6_enable
   ifeq ($(ipv6_enable),0)
       ipv6arg="disable_ipv6_offload=1"
   else
       ipv6arg=  
   endif
else
   ipv6arg= 
endif

is_separate_ipv6 = 0
is_build_against_oiscsi = 0
is_not_build_against_oiscsi = 0
is_separate_ipv6_kernel_support = 
is_build_against_oiscsi_kernel_support = sles11sp1 sles11 rhel5u3 \
                                         rhel5u4 rhel5u5 rhel5u6 rhel5u7
is_not_build_against_oiscsi_kernel_support = rhel6 rhel6u1 rhel6u2 rhel6u3 rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel7 rhel7u1 rhel7u2 kernel26u34 \
                                             kernel26u35 ubuntu12u042 ubuntu14u041 sles12 sles12sp1 ubuntu12u042 \
                                             kernel26u36 kernel26u37 kernel26u39 rhel5u8 rhel5u9 rhel5u10 rhel5u11 kernel3u5\
                                             ubuntu12u04 sles11sp2 kernel3u1 ubuntu14u041 ubuntu14u042 ubuntu14u043 kernel3u6 sles11sp3 sles11sp4 kernel3u7 kernel3u4 \
                                             kernel3u8 kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 kernel4u1
all_special_target =  is_separate_ipv6 is_build_against_oiscsi is_not_build_against_oiscsi
$(foreach tgt,$(all_special_target), $(if $(filter $(dist), $(value $(tgt)_kernel_support)),\
                                $(eval $(call enable_tgt,$(tgt))),$(eval $(call disable_tgt,$(tgt)))))
ifeq ($(DEBUG),1)
    $(foreach tgt,$(all_special_target), $(info INFO : $(tgt) : $(value $(tgt))))
endif

ifeq ($(bonding_mode),1)
  bond_setflag="disable_bonding=0"
else
  bond_setflag=
endif

ifeq ($(wdtoe_mode),1)
  wdtoe_set="enable_wdtoe=1"
else
  wdtoe_set=
endif

ifeq ($(wildcard $(oiscsiSrc)),)
ifneq ($(filter $(kdist),RHEL6.4 RHEL6.5 RHEL6.6 RHEL6.7 RHEL7.0 RHEL7.1 RHEL7.2 SLES11sp3 SLES11sp4 SLES12 SLES12sp1 Debian ubuntu-14.04.1 ubuntu-14.04.3 ubuntu-14.04.2), )
  $(shell ln -s $(oiscsiSrc3) $(oiscsiSrc))
else
  $(shell ln -s $(oiscsiSrc2) $(oiscsiSrc))
endif
endif

.PHONY: all
all: vnic iwarp toe iscsi_target oiscsi

.PHONY: install
install: vnic_install iwarp_install toe_install iscsi_target_install oiscsi_install

.PHONY: nic
nic:
	@ echo "################################################## " ;\
	  echo "#          Building Network Drivers              # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               nic $(ipv6arg) && $(call logs,Network(NIC),cxgb4,Build) ) \
	       || $(call logtemp,Network(NIC),cxgb4,Build)

.PHONY: nic_offload
nic_offload:
	@ echo "################################################## " ;\
	  echo "#   Building Offload Capable Network Drivers     # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               lld $(ipv6arg) $(bond_setflag) $(wdtoe_set) && $(call logs,Network(NIC),cxgb4,Build) ) \
               || $(call logtemp,Network(NIC),cxgb4,Build)

.PHONY: nic_ipv4
nic_ipv4:
	@ echo "################################################## " ;\
          echo "#   Building Offload Capable Network Drivers     # " ;\
          echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          lld disable_ipv6_offload=1 $(bond_setflag) && $(call logs,Network(NIC_IPV4),cxgb4,Build) \
          ) || $(call logtemp,Network(NIC_IPV4),cxgb4,Build)

.PHONY: nic_bypass
nic_bypass:
	@ echo "################################################## " ;\
	  echo "#  Building Network Drivers and utils (bypass)   # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	       bypass $(ipv6arg) && $(call logs,Network-Offload(Bypass),cxgb4,Build) \
	       ) || $(call logtemp,Network-Offload(Bypass),cxgb4,Build)

.PHONY: bonding
bonding:
	@ echo "################################################## " ;\
	  echo "#     Building Bonding Drivers (offload)         # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               chbonding $(ipv6arg) $(wdtoe_set) && $(call logs,Bonding-offload,bonding,Build) \
               ) || $(call logtemp,Bonding-offload,bonding,Build)

.PHONY: vnic
vnic:
	@ echo "################################################## " ;\
	  echo "#      Building virtual Network Drivers          # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               vnic $(ipv6arg) && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,Build) \
              ) || $(call logtemp,SR-IOV_networking(vnic),cxgb4vf,Build)

.PHONY: toe
toe:
	@ echo "################################################## " ;\
	  echo "#      Building Network Drivers (offload)        # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	              toe $(ipv6arg) $(bond_setflag) $(wdtoe_set) && $(call logs,Network-offload(TOE),t4_tom,Build) \
		      if [ $(is_udp_offload) -eq 1 ] ; then \
			$(call logs,UDP_offload,t4_tom,Build) \
		      fi ; \
		      if [ $(ipv6_enable) -ne 0 ] ; then \
		          $(call logs,IPv6-offload,t4_tom,Build) \
                      fi ; ) \
                      || $(call logtemp,Network-offload(TOE),t4_tom,Build)

.PHONY: wdtoe
wdtoe:
	@ echo "################################################## " ;\
          echo "#      Building WD-TOE Drivers (offload)         # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                  toe enable_wdtoe=1 $(ipv6arg) $(bond_setflag) && $(call logs,WD-TOE,t4_tom,Build) ) \
	  || $(call logtemp,WD-TOE,t4_tom,Build)


.PHONY: toe_ipv4
toe_ipv4:
	@ echo "################################################## " ;\
	  echo "#      Building Network Drivers (offload)        # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          toe disable_ipv6_offload=1 $(bond_setflag) $(wdtoe_set) && $(call logs,Network-offload(TOE),t4_tom,Build) \
		  if [ $(is_udp_offload) -eq 1 ] ; then \
                     $(call logs,UDP_Offload,t4_tom,Build) \
		  fi ; \
	          ) || $(call logtemp,Network-offload(TOE),t4_tom,Build)

.PHONY: ipv6
ipv6:
	@ echo "################################################## " ;\
          echo "#      Building ipv6 Drivers (offload)           # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          SUBDIRS="toecore ipv6" && $(call logs,IPv6-offload,ipv6,Build) \
          ) || $(call logtemp,IPv6-offload,ipv6,Build)

.PHONY: toe_ipv6
toe_ipv6:
	@ echo "################################################## " ;\
          echo "#      Building ipv6 Drivers (offload)           # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          toe disable_ipv6_offload=0 $(bond_setflag) $(wdtoe_set) && $(call logs,IPv6-offload,ipv6,Build) \
          ) || $(call logtemp,IPv6-offload,ipv6,Build)

.PHONY: iwarp
iwarp:
	@ echo "################################################## " ;\
	  echo "#   Building iWARP Drivers (offload)             # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               iwarp $(ipv6arg) $(bond_setflag) $(wdtoe_set) && $(call logs,RDMA(iWARP),iw_cxgb4,Build) \
              ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,Build)

.PHONY:udp_offload
udp_offload:
	@ echo "################################################## " ;\
          echo "# Building UDP Offload Capable Network Drivers   # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                   toe $(ipv6arg) $(bond_setflag) $(wdtoe_set) && $(call logs,Network(UDP-Offload),t4_tom,Build) $(call logs,IPv6-offload,t4_tom,Build) \
                  ) || $(call logtemp,Network(UDP-Offload),t4_tom,Build)

.PHONY: fcoe
fcoe:
	@ echo "################################################## " ;\
	  echo "#       Building FCoE Drivers (Initiator)        # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  storage && $(call logs,FCoE(full-offload-initiator),csiostor,Build) \
	  ) || ( $(call logtemp,FCoE(full-offload-initiator),csiostor,Build) )

.PHONY: fcoe_target
fcoe_target:scst_kernel_install scst_user_install
	@ echo "################################################## " ;\
	  echo "#       Building FCoE Drivers (Target)           # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(fcoeTgtSrc) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	   && $(call logs,FCoE(full-offload-target),csioscst,Build) \
	  ) || $(call logtemp,FCoE(full-offload-target),csioscst,Build)

.PHONY: scst_kernel
scst_kernel:
	@ echo "################################################## " ;\
	  echo "#           Building SCST Drivers                # " ;\
	  echo "################################################## " ;
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ) debug2perf clean
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ)

.PHONY: scst_user
scst_user:
	@ echo "################################################## " ;\
	  echo "#           Building SCST utils                  # " ;\
	  echo "################################################## " ;
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scstadmin-2.0.0
		

.PHONY: iscsi_target
iscsi_target:
	@ echo "################################################## " ;\
	  echo "#    Building Chelsio iSCSI Target and Drivers   # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -k -i -C $(chiscsiSrc) CXGB4TOE_SRC=$(cxgb4Src) \
	  KSRC=$(KSRC) KOBJ=$(KOBJ) && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,Build) \
	  ) || $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Build)

.PHONY: oiscsi
oiscsi:
	@ echo "################################################## " ;\
	  echo "#   Building open iSCSI Initiator and Drivers    # " ;\
	  echo "################################################## " ; \
	  if [ $(shell echo $(dist) | grep sles ) ] ; then \
		( $(MAKE) -i --no-print-directory -C $(oiscsiSrc) \
		KSRC=$(KSRC) KBUILD_OUTPUT=$(KOBJ)) \
	  elif [ $(is_not_build_against_oiscsi) -eq 1 ] ; then \
		( $(MAKE) -i --no-print-directory -C $(oiscsiSrc) user) \
	  else \
		( $(MAKE) -j 12 -i -k --no-print-directory -C $(oiscsiSrc) KSRC=$(KSRC)\
		 KOBJ=$(KOBJ) ) \
	  fi ;

.PHONY: cxgbi
cxgbi: oiscsi
	@ echo "################################################## " ;\
	  echo "#   Building open iSCSI Data path Accelerator   # " ;\
	  echo "################################################## " ; \
	  if [ $(is_not_build_against_oiscsi) -eq 1  ] ; then \
		( $(MAKE) --no-print-directory -C cxgbi CXGB4TOE_SRC=$(cxgb4Src) KSRC=$(KSRC) \
                  KOBJ=$(KOBJ) && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Build) \
                  ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Build) \
	  else \
		( $(MAKE) --no-print-directory -C cxgbi CXGB4TOE_SRC=$(cxgb4Src) KSRC=$(KSRC) \
		KOBJ=$(KOBJ) OISCSI_SRC=$(oiscsiSrc) && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Build) \
		) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Build) \
	  fi;

.PHONY: scst_chfcoe
scst_chfcoe:
	@ echo "####################################### " ;\
          echo "#        Building scst Drivers        # " ;\
          echo "####################################### " ;
	@ ( $(MAKE) --no-print-directory -C $(scstSrc) 2release KDIR=$(KOBJ) && \
            $(MAKE) --no-print-directory -C $(scstSrc) scst  KDIR=$(KOBJ) && \
	    $(MAKE) --no-print-directory -C $(scstSrc) scstadm KDIR=$(KOBJ)  )

.PHONY: chfcoe
chfcoe: 
	@ echo "####################################### " ;\
          echo "#        Building chfcoe Drivers      # " ;\
          echo "####################################### " ;
	@ ( $(MAKE) -C $(chfcoeSrc) CXGB4_SRC_PATH=$(cxgb4Src)/cxgb4 \
          CSIOSTOR_SRC_PATH=$(csioSrc) FIRMWARE_PATH=$(firmwarePath) target=1  KSRC=$(KSRC) KDIR=$(KOBJ) && \
          $(call logs,FCoE(pdu-offload-target),chfcoe,Build) ) || \
          $(call logtemp,FCoE(pdu-offload-target),chfcoe,Build)

.PHONY: rdma_block
rdma_block:
	@ echo "################################################# " ;\
          echo "#	Building rdma block device Drivers	# " ;\
          echo "################################################# " ;
	@ ( $(MAKE) --no-print-directory -C $(rdmablkSrc) && \
          $(call logs,RDMA-Block-Device,RDMA,Build) ) || \
          $(call logtemp,RDMA-Block-Device,RDMA,Build)
	
.PHONY: nic_install
nic_install: 
	@ echo "################################################## " ;\
	  echo "#         Installing Network Drivers             # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                 nic $(ipv6arg) install && $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware \
                 install && $(call logs,Network(NIC),cxgb4,Install) ) \
                 || $(call logtemp,Network(NIC),cxgb4,Install)

.PHONY: nic_offload_install
nic_offload_install: 
	@ echo "################################################## " ;\
	  echo "#    Installing Offload Capable Network Drivers  # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                 lld $(ipv6arg) $(wdtoe_set) install && $(MAKE) --no-print-directory -C \
                 $(cxgb4Src)/firmware install && $(call logs,Network(NIC),cxgb4,Install) ) \
                 || $(call logtemp,Network(NIC),cxgb4,Install)

.PHONY: nic_ipv4_install
nic_ipv4_install:
	@ echo "################################################## " ;\
          echo "#    Installing Offload Capable Network Drivers  # " ;\
          echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  lld disable_ipv6_offload=1 $(wdtoe_set) install && $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware \
	   install && $(call logs,Network(NIC_IPV4),cxgb4,Install )  \
	   $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware install ; \
	  ) || $(call logtemp,Network(NIC_IPV4),cxgb4,Install)


.PHONY: nic_bypass_install
nic_bypass_install: 
	@ echo "################################################## " ;\
	  echo "#    Installing Network Drivers (bypass)         # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               bypass $(ipv6arg) install && \
               $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware \
               install && $(call logs,Network-Offload(Bypass),cxgb4,Install) \
              ) || $(call logtemp,Network-Offload(Bypass),cxgb4,Install)

.PHONY: bonding_install
bonding_install:
	@ echo "################################################## " ;\
	  echo "#     Installing Bonding Drivers ( offload)      # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
              chbonding $(ipv6arg) $(wdtoe_set) install && $(call logs,Bonding-offload,bonding,Install) \
             ) || $(call logtemp,Bonding-offload,bonding,Install) \

.PHONY: vnic_install
vnic_install:
	@ echo "################################################## " ;\
	  echo "#       Installing Virtual Network Drivers       # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
               vnic $(ipv6arg) install && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,Install) \
             ) || $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Install) 

.PHONY: toe_install
toe_install:
	@ echo "################################################## " ;\
	  echo "#      Installing Network Drivers (offload)      # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	            toe $(ipv6arg) $(wdtoe_set) install && $(call logs,Network-offload(TOE),t4_tom,Install) \
		    if [ $(is_udp_offload) -eq 1 ] ; then \
	               $(call logs,UDP_offload,t4_tom,Install) \
		    fi ; \
		    if [ $(ipv6_enable) -eq 1 ] ; then \
                        $(call logs,IPv6-offload,t4_tom,Install) \
		    fi; ) \
                    || $(call logtemp,Network-offload(TOE),t4_tom,Install)

.PHONY: wdtoe_install
wdtoe_install:
	@ echo "################################################## " ;\
          echo "#      Installing WD-TOE Drivers (offload)       # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                   toe enable_wdtoe=1 $(ipv6arg) install && \
	           $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware install && \
	           $(call logs,WD-TOE,t4_tom,Install) \
                   ) || $(call logtemp,WD-TOE,t4_tom,Install)

.PHONY: toe_ipv4_install
toe_ipv4_install:
	@ echo "################################################## " ;\
	  echo "#      Installing Network Drivers (offload)      # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          toe disable_ipv6_offload=1 $(wdtoe_set) install && \
	          $(call logs,Network-offload(TOE),t4_tom,Install) \
	          $(call logs,UDP_Offload,t4_tom,Install) \
	          ) || $(call logtemp,Network-offload(TOE),t4_tom,Install)

.PHONY:ipv6_install
ipv6_install:
	@ echo "################################################## " ;\
          echo "#      Installing ipv6 Drivers (offload)         # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          SUBDIRS="toecore ipv6" install && $(call logs,IPv6-offload,ipv6,Install) \
          ) || $(call logtemp,IPv6-offload,ipv6,Install)


.PHONY:toe_ipv6_install
toe_ipv6_install:
	@ echo "################################################## " ;\
          echo "#      Installing ipv6 Drivers (offload)         # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          toe disable_ipv6_offload=0 $(wdtoe_set) install && $(call logs,IPv6-offload,ipv6,Install) \
          ) || $(call logtemp,IPv6-offload,ipv6,Install)

.PHONY: iwarp_install
iwarp_install:
	@ echo "################################################## " ;\
	  echo "#  Installing iWARP Drivers (offload)            # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	      iwarp $(ipv6arg) $(bond_setflag) $(wdtoe_set) install && $(call logs,RDMA(iWARP),iw_cxgb4,Install) \
	      ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,Install)

.PHONY:udp_offload_install
udp_offload_install:
	@ echo "################################################## " ;\
          echo "# Installing UDP Offload Capable Network Drivers # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                   toe $(ipv6arg) install && $(call logs,Network(UDP-Offload),t4_tom,Install) \
                   ) || $(call logtemp,Network(UDP-Offload),t4_tom,Install) 

.PHONY: fcoe_install
fcoe_install:
	@ echo "################################################## " ;\
	  echo "#       Installing FCoE Drivers (Initiator)      # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  storage install && $(call logs,FCoE(full-offload-initiator),csiostor,Install) \
	  ) || $(call logtemp,FCoE(full-offload-initiator),csiostor,Install)

.PHONY: fcoe_target_install
fcoe_target_install:scst_kernel_install scst_user_install
	@ echo "################################################## " ;\
	  echo "#       Installing FCoE Drivers (Target)         # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(fcoeTgtSrc) KSRC=$(KSRC) KOBJ=$(KOBJ) install \
	   && $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware install && \
	   install -D -m 644 -v ${cxgb4Src}/firmware/fcoe_target_config/t4-config.txt /lib/firmware/cxgb4/t4-config.txt && \
	   $(call logs,FCoE(full-offload-target),csioscst,Install) \
	  ) || $(call logtemp,FCoE(full-offload-target),csioscst,Install)

.PHONY: scst_kernel_install
scst_kernel_install:
	@ echo "################################################## " ;\
	  echo "#          Installing SCST Drivers               # " ;\
	  echo "################################################## " ;
	-@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ) debug2perf clean && \
	   $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ) && \
	   $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ) install

.PHONY: scst_user_install
scst_user_install:
	@ echo "################################################## " ;\
	  echo "#           Installing SCST utils                # " ;\
	  echo "################################################## " ;
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scstadmin-2.0.0 install
		
.PHONY: iscsi_target_install
iscsi_target_install: iscsi_tgt_utils_install
	@ echo "################################################### " ;\
	  echo "#   Installing Chelsio iSCSI Target and Drivers   # " ;\
	  echo "################################################### " ;
	@ ( $(MAKE) --no-print-directory -k -i -C $(chiscsiSrc) CXGB4TOE_SRC=$(cxgb4Src) \
	  KSRC=$(KSRC) KOBJ=$(KOBJ) install && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,Install) \
	  ) || $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Install)

.PHONY: iscsi_tgt_utils_install
iscsi_tgt_utils_install:
	@ if [ $(shell uname -m) == "x86_64" ] ; then \
	        if [ -f $(chiscsiSrc)/user/chinfotool64 ] ; then \
		    install -v -m 744 $(chiscsiSrc)/user/chinfotool64 /sbin/chinfotool ; \
		fi ; \
	  else \
	        if [ -f $(chiscsiSrc)/user/chinfotool32 ] ; then \
		   install -v -m 744 $(chiscsiSrc)/user/chinfotool32 /sbin/chinfotool ; \
	        fi ; \
	  fi ; 

.PHONY: oiscsi_install
oiscsi_install: pre
	@ echo "################################################## " ;\
	  echo "#   Installing open iSCSI Initiator and Drivers  # " ;\
	  echo "################################################## " ;\
	  if [ $(is_not_build_against_oiscsi) -eq 1 ] ; then \
		( ( /usr/bin/install -D -m 755 $(oiscsiSrc)/usr/iscsiadm /sbin/iscsiadm && echo "install iscsiadm" ; \
                /usr/bin/install -D -m 755 $(oiscsiSrc)/usr/iscsid /sbin/iscsid && echo "install iscsid" ) ) \
	  elif [ $(shell echo $(dist) | grep sles ) ] ; then \
	        if [ '$(arch)' == 'i386' ] ; then \
			( $(MAKE) -C $(oiscsiSrc) -j 12 KSRC='/usr/src/linux' \
			KBUILD_OUTPUT='/usr/src/linux-obj/i386/default' \
			install ) \
		elif [ '$(arch)' == 'i686' ] ; then \
			( $(MAKE) -C $(oiscsiSrc) -j 12  KSRC='/usr/src/linux' \
			KBUILD_OUTPUT='/usr/src/linux-obj/i686/default' \
			install) \
		else  \
			( $(MAKE) -C $(oiscsiSrc) -j 12 KSRC='/usr/src/linux' \
			KBUILD_OUTPUT='/usr/src/linux-obj/x86_64/default' \
			install ) \
		fi;\
	  elif [ $(is_build_against_oiscsi) -eq 1 ] ; then \
		( $(MAKE) -j 12 -i -k --no-print-directory -C $(oiscsiSrc) install )\
	  fi ;
	@ $(MAKE) --no-print-directory postuninstall

.PHONY: cxgbi_install
cxgbi_install: oiscsi_install
	@ echo "################################################## " ;\
	  echo "#   Installing open iSCSI Data path Accelerator  # " ;\
	  echo "################################################## " ; \
	  if [ -f cxgbi/cxgb4i/cxgb4i.ko ] && [ -f cxgbi/libcxgbi/libcxgbi.ko ] ;then \
	      if [ $(is_not_build_against_oiscsi) == 1 ]; then \
	           ( $(MAKE) --no-print-directory -C cxgbi CXGB4TOE_SRC=$(cxgb4Src) \
                   install && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Install) \
                   ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Install) \
	      elif [ $(is_build_against_oiscsi) -eq 1 ]; then \
		   ( $(MAKE) --no-print-directory -C cxgbi CXGB4TOE_SRC=$(cxgb4Src) \
		     OISCSI_SRC=$(oiscsiSrc) install && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Install) \
		   ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Install) \
	      fi; \
	  else \
	      $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Install)\
	  fi ;

.PHONY: scst_chfcoe_install
scst_chfcoe_install: scst_chfcoe
	@ echo "######################################### " ;\
          echo "#       Installing scst Drivers	        # " ;\
          echo "######################################### " ;
	@ ( $(MAKE) --no-print-directory -C $(scstSrc) scst_install KDIR=$(KOBJ) && \
            $(MAKE) --no-print-directory -C $(scstSrc) scstadm_install KDIR=$(KOBJ) )

.PHONY: chfcoe_install
chfcoe_install: 
	@ echo "########################################## " ;\
          echo "#        Installing chfcoe Drivers       # " ;\
          echo "########################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(chfcoeSrc) CXGB4_SRC_PATH=$(cxgb4Src)/cxgb4 \
          CSIOSTOR_SRC_PATH=$(csioSrc) FIRMWARE_PATH=$(firmwarePath) target=1 install && \
          $(call logs,FCoE(pdu-offload-target),chfcoe,Install) ) || \
          $(call logtemp,FCoE(pdu-offload-target),chfcoe,Install)

.PHONY: rdma_block_install
rdma_block_install:
	@ echo "################################################# " ;\
          echo "#	Installing rdma block device Drivers	# " ;\
          echo "################################################# " ;
	@ ( $(MAKE) --no-print-directory -C $(rdmablkSrc) install && \
          $(call logs,RDMA-Block-Device,RDMA,Install) ) || \
	  $(call logtemp,RDMA-Block-Device,RDMA,Install)

.PHONY: nic_uninstall
nic_uninstall:
	@ echo "################################################## " ;\
	  echo "#          Uninstalling Network Drivers          # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="cxgb4" uninstall && $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware \
	  uninstall && $(call logs,Network(NIC),cxgb4,Uninstall) \
	  ) || $(call logtemp,Network(NIC),cxgb4,Uninstall)

.PHONY: nic_bypass_uninstall
nic_bypass_uninstall:
	@ echo "################################################## " ;\
	  echo "#      Uninstalling Network Drivers (bypass)     # " ;\
	  echo "################################################## " ;
	@ rm -f /etc/modprobe.d/chelsio.conf ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	    SUBDIRS="cxgb4 toecore t4_tom iw_cxgb4" uninstall && $(MAKE) --no-print-directory -C $(cxgb4Src)/firmware \
	    uninstall && $(call logs,Network-Offload(Bypass),cxgb4,Uninstall) \
	  ) || $(call logtemp,Network-Offload(Bypass),cxgb4,Uninstall)

.PHONY: bonding_uninstall
bonding_uninstall:
	@ echo "################################################## " ;\
	  echo "#     Uninstalling Bonding Drivers  (offload)    # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="bonding" uninstall && $(call logs,Bonding-offload,bonding,Uninstall) \
	  ) || $(call logtemp,Bonding-offload,bonding,Uninstall)

.PHONY: vnic_uninstall
vnic_uninstall:
	@ echo "################################################## " ;\
	  echo "#      Uninstalling Virtual Network Drivers      # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="cxgb4vf" uninstall && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,Uninstall) \
	  ) || $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Uninstall)

.PHONY: toe_uninstall
toe_uninstall:
	@ echo "################################################## " ;\
	  echo "#      Uninstalling Network Drivers (offload)     # " ;\
	  echo "################################################## " ;
	@ if [ $(is_separate_ipv6) -eq 1 ] ; then \
	       ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          SUBDIRS="toecore ipv6 t4_tom" uninstall && $(call logs,Network-offload(TOE),t4_tom,Uninstall) \
		  if [ $(is_udp_offload) -eq 1 ] ; then \
		   $(call logs,UDP_Offload,t4_tom,Uninstall) \
		  fi ; \
	          ) || $(call logtemp,Network-offload(TOE),t4_tom,Uninstall) \
	  else \
	       ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          SUBDIRS="toecore t4_tom " uninstall && $(call logs,Network-offload(TOE),t4_tom,Uninstall) \
		  if [ $(is_udp_offload) -eq 1 ] ; then \
                   $(call logs,UDP_Offload,t4_tom,Uninstall) \
                  fi ; \
		  if [ $(ipv6_enable) -eq 1 ] ; then \
		     $(call logs,IPv6_Offload,t4_tom,Uninstall) \
		  fi ; \
	          ) || $(call logtemp,Network-offload(TOE),t4_tom,Uninstall) \
	  fi ;

.PHONY: wdtoe_uninstall
wdtoe_uninstall:
	@ echo "################################################## " ;\
          echo "#      Uninstalling WD-TOE Drivers (offload)     # " ;\
          echo "################################################## " ;
	@ if [ $(is_separate_ipv6) -eq 1 ] ; then \
               ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                  SUBDIRS="cxgb4 toecore ipv6 t4_tom" uninstall && $(call logs,Network-offload(WD-TOE),t4_tom,Uninstall) \
                  ) || $(call logtemp,Network-offload(WD-TOE),t4_tom,Uninstall) \
          else \
               ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                  SUBDIRS="cxgb4 toecore t4_tom firmware" uninstall && $(call logs,Network-offload(WD-TOE),t4_tom,Uninstall) \
                  ) || $(call logtemp,Network-offload(WD-TOE),t4_tom,Uninstall) \
          fi ;


.PHONY: toe_ipv4_uninstall
toe_ipv4_uninstall:
	@ echo "################################################## " ;\
	  echo "#      Uninstalling Network Drivers (offload)     # " ;\
	  echo "################################################## " ;
	@ if [ $(is_separate_ipv6) -eq 1 ] ; then \
	       ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          SUBDIRS="toecore t4_tom" disable_ipv6_offload=1 uninstall && $(call logs,Network-offload(TOE),t4_tom,Uninstall) \
	          ) || $(call logtemp,Network-offload(TOE),t4_tom,Uninstall) \
	  else \
	       ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	          SUBDIRS="toecore t4_tom " disable_ipv6_offload=1 uninstall && $(call logs,Network-offload(TOE_IPV4),t4_tom,Uninstall) \
	          ) || $(call logtemp,Network-offload(TOE_IPV4),t4_tom,Uninstall) \
	  fi ;

.PHONY: ipv6_uninstall
ipv6_uninstall:
	@ echo "################################################## " ;\
          echo "#      Unistalling ipv6 Drivers (offload)        # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          SUBDIRS="toecore ipv6" uninstall )

.PHONY: toe_ipv6_uninstall
toe_ipv6_uninstall:
	@ echo "################################################## " ;\
          echo "#      Unistalling ipv6 Drivers (offload)        # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
          SUBDIRS="toecore t4_tom" uninstall )

.PHONY: iwarp_uninstall
iwarp_uninstall:
	@ echo "################################################## " ;\
	  echo "#  Unistalling iWARP Drivers (offload)           # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="iw_cxgb4" uninstall && $(call logs,RDMA(iWARP),iw_cxgb4,Uninstall) \
	  ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,Uninstall)

.PHONY:udp_offload_uninstall
udp_offload_uninstall:
	@ echo "#################################################### " ;\
          echo "# Uninstalling UDP Offload Capable Network Drivers # " ;\
	  echo "#################################################### " ;
	@ if [ $(is_separate_ipv6) -eq 1 ] ; then \
               ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                  SUBDIRS="toecore ipv6 t4_tom" uninstall && $(call logs,Network(UDP-Offload),t4_tom,Uninstall) \
                  ) || $(call logtemp,Network(UDP-Offload),t4_tom,Uninstall) \
          else \
               ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
                  SUBDIRS="toecore t4_tom " uninstall && $(call logs,Network(UDP-Offload),t4_tom,Uninstall) \
                  ) || $(call logtemp,Network(UDP-Offload),t4_tom,Uninstall) \
          fi ;

.PHONY: fcoe_uninstall
fcoe_uninstall:
	@ echo "################################################## " ;\
	  echo "#       Uninstalling FCoE Drivers (Initiator)    # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="csiostor" uninstall && $(call logs,FCoE(full-offload-initiator),csiostor,Uninstall) \
	  ) || ( $(call logtemp,FCoE(full-offload-initiator),csiostor,Uninstall) ) 

.PHONY: fcoe_target_uninstall
fcoe_target_uninstall:
	@ $(MAKE) --no-print-directory -C $(cxgb4Src) KSRC=$(KSRC) KOBJ=$(KOBJ) \
	  SUBDIRS="csiostor" uninstall
	-@ rm -rf /lib/modules/$(shell uname -r)/updates/kernel/drivers/scsi/csioscst

.PHONY: chfcoe_uninstall
chfcoe_uninstall: 
	@ echo "########################################## " ;\
          echo "#      Uninstalling chfcoe Drivers       # " ;\
          echo "########################################## " ;
	@ ( $(MAKE) --no-print-directory -C $(chfcoeSrc) CXGB4_SRC_PATH=$(cxgb4Src)/cxgb4 \
          CSIOSTOR_SRC_PATH=$(csioSrc) FIRMWARE_PATH=$(firmwarePath) uninstall && \
          $(call logs,FCoE(pdu-offload-target),chfcoe,Uninstall) ) || \
          $(call logtemp,FCoE(pdu-offload-target),chfcoe,Uninstall)

.PHONY: scst_kernel_uninstall
scst_kernel_uninstall:
	@ echo "################################################## " ;\
	  echo "#        Uninstalling SCST Drivers               # " ;\
	  echo "################################################## " ;
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scst-2.0.0.1 KSRC=$(KSRC) KDIR=$(KOBJ) uninstall

.PHONY: scst_user_uninstall
scst_user_uninstall:
	@ echo "################################################## " ;\
	  echo "#           Uninstalling SCST utils              # " ;\
	  echo "################################################## " ;
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scstadmin-2.0.0 perl-module
	@ $(MAKE) --no-print-directory -C $(shell pwd)/scst/scstadmin-2.0.0 uninstall
		
.PHONY: iscsi_target_uninstall
iscsi_target_uninstall: iscsi_tgt_utils_uninstall
	@ echo "################################################## " ;\
	  echo "# Uninstalling Chelsio iSCSI Target and Drivers  # " ;\
	  echo "################################################## " ;
	@ ( $(MAKE) --no-print-directory -k -i -C $(chiscsiSrc) CXGB4TOE_SRC=$(cxgb4Src) \
	  KSRC=$(KSRC) KOBJ=$(KOBJ) uninstall && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,Uninstall) \
	  ) || $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Uninstall)

.PHONY: iscsi_tgt_utils_uninstall
iscsi_tgt_utils_uninstall:
	@ if [ $(shell uname -m) == "x86_64" ] ; then \
		rm -f /sbin/chinfotool ; \
	  else \
		rm -f /sbin/chinfotool ; \
	  fi ; 

.PHONY: oiscsi_uninstall
oiscsi_uninstall:
	@ echo "################################################## " ;\
	  echo "# Uninstalling open iSCSI Initiator and Drivers  # " ;\
	  echo "################################################## " ;\
	  ( $(MAKE) --no-print-directory -C $(oiscsiSrc) uninstall )
	@ echo "################################################## " ;\
	  echo "# Uninstalling open iSCSI data path Accelerator  # " ;\
	  echo "################################################## " ;\
	  ( $(MAKE) --no-print-directory -C cxgbi CXGB4TOE_SRC=$(cxgb4Src) \
	  uninstall && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Uninstall) \
	  ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Uninstall)
	@ $(MAKE) --no-print-directory postuninstall

.PHONY: rdma_block_uninstall
rdma_block_uninstall:
	@ echo "################################################# " ;\
          echo "#    Uninstalling rdma block device Drivers	# " ;\
          echo "################################################# " ;
	@ ( $(MAKE) --no-print-directory -C $(rdmablkSrc) uninstall && \
          $(call logs,RDMA-Block-Device,RDMA,Uninstall) ) || \
	  $(call logtemp,RDMA-Block-Device,RDMA,Uninstall)

.PHONY: uninstall
uninstall: vnic_uninstall iwarp_uninstall toe_uninstall iwarp_uninstall oiscsi_uninstall iscsi_target_uninstall
	@ echo "Uninstall done"

.PHONY: pre
pre: postuninstall
	@ if [ $(is_build_against_oiscsi) -eq 1 ] ; then \
		if [ -f /sbin/iscsiadm ] ; then \
			mv -f /sbin/iscsiadm /usr/sbin/iscsiadm ; \
		fi ; \
		if [ -f /sbin/iscsid ] ; then \
			mv -f /sbin/iscsid /usr/sbin/iscsid ; \
		fi ; \
	  else \
		if [ -f /sbin/iscsiadm ] ; then \
			mv -f /sbin/iscsiadm /usr/sbin/iscsiadm ; \
		fi ; \
		if [ -f /sbin/iscsid ] ; then \
			mv -f /sbin/iscsid /usr/sbin/iscsid ; \
		fi ; \
		if [ -f /sbin/iscsi-iname ] ; then \
			mv -f /sbin/iscsi-iname /usr/sbin/iscsi-iname ; \
		fi ; \
		if [ -f /etc/iscsi/iscsid.conf ] ; then \
			mv -f /etc/iscsi/iscsid.conf /etc/iscsi/iscsid.conf_bak ; \
		fi ;\
	  fi ;

.PHONY: post
post:
	@ if [ $(is_build_against_oiscsi) -eq 1 ] ; then \
		mv /sbin/iscsiadm /sbin/iscsiadm2 ; \
		mv /sbin/iscsid /sbin/iscsid2 ; \
		ln -s /sbin/iscsiadm2 /sbin/iscsiadm ; \
		ln -s /sbin/iscsid2 /sbin/iscsid ; \
	  else \
		mv /sbin/iscsiadm /sbin/iscsiadm2 ; \
		mv /sbin/iscsid /sbin/iscsid2 ; \
		mv /sbin/iscsi-iname /sbin/iscsi-iname2 ; \
		mv /etc/iscsi/iscsid.conf /etc/iscsi/iscsid.conf.2 ; \
		if [ -f /sbin/iscsiadm2 ] ; then \
			ln -s /sbin/iscsiadm2 /sbin/iscsiadm ; \
		fi ; \
		if [ -f /sbin/iscsid2 ] ; then \
			ln -s /sbin/iscsid2 /sbin/iscsid ; \
		fi ; \
		if [ -f /sbin/iscsi-iname2 ] ; then \
			ln -s /sbin/iscsi-iname2 /sbin/iscsi-iname ; \
		fi ; \
		if [ -f /etc/iscsi/iscsid.conf.2 ] ; then \
			ln -s /etc/iscsi/iscsid.conf.2 /etc/iscsi/iscsid.conf ; \
		fi ;\
	  fi ;

.PHONY: postuninstall
postuninstall:
	@ if [ $(is_build_against_oiscsi) -eq 1 ] ; then \
		if [ -f /sbin/iscsiadm2 ] ; then \
			rm -rf /sbin/iscsiadm ;\
			rm -rf /sbin/iscsiadm2 ;\
		fi ; \
		if [ -f /sbin/iscsiadm1 ] ; then \
			mv /sbin/iscsiadm1 /sbin/iscsiadm ; \
		fi ; \
		if [ -f /sbin/iscsid2 ] ; then \
			rm -rf /sbin/iscsid ;\
			rm -rf /sbin/iscsid2 ;\
		fi ; \
		if [ -f /sbin/iscsid1 ] ; then \
			mv /sbin/iscsid1 /sbin/iscsid ; \
		fi ; \
		rm -rf /sbin/iscsiadm2 /sbin/iscsid2 ; \
	  else \
		if [ -f /sbin/iscsiadm2 ] ; then \
			rm -rf /sbin/iscsiadm ;\
			rm -rf /sbin/iscsiadm2 ;\
		fi ; \
		if [ -f /sbin/iscsiadm1 ] ; then \
			mv /sbin/iscsiadm1 /sbin/iscsiadm ; \
		fi ; \
		if [ -f /sbin/iscsid2 ] ; then \
			rm -rf /sbin/iscsid ;\
			rm -rf /sbin/iscsid2 ;\
		fi ; \
		if [ -f /sbin/iscsid1 ] ; then \
			mv /sbin/iscsid1 /sbin/iscsid ; \
		fi ; \
		if [ -f /sbin/iscsi-iname2 ] ; then \
			rm -rf /sbin/iscsi-iname ;\
			rm -rf /sbin/iscsi-iname2 ;\
		fi ; \
		if [ -f /sbin/iscsi-iname1 ]  ; then \
			mv /sbin/iscsi-iname1 /sbin/iscsi-iname ; \
		fi ; \
		if [ -f /etc/iscsi/iscsid.conf.2 ] ; then \
			rm -rf /etc/iscsi/iscsid.conf.2 /etc/iscsi/iscsid.conf ; \
		fi; \
		if [ -f /etc/iscsi/iscsid.conf.1 ] ; then \
			mv /etc/iscsi/iscsid.conf.1 /etc/iscsi/iscsid.conf ; \
		fi; \
		rm -rf /sbin/iscsiadm2 /sbin/iscsid2 /sbin/iscsi-iname2 ; \
	  fi ;

define logtemp
echo -e "$1\t\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log ;
endef
