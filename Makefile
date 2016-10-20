SHELL := /bin/bash
NwSrc := build/src
FwSrc := build/src/network/firmware
FwTar := /lib/firmware/cxgb4/
ToolSrc := build/tools
LibSrc := build/libs
SnifferSrc  := build/tools/sniffer
specs := specs
debrules := debrules
DEBIAN := 0
PDEB := 0
logpath := $(shell pwd)
pwd := $(shell pwd)
arch := $(shell uname -p)
rpmLoc := $(shell pwd)/rpmbuild/RPMS/$(arch)
removelogs := $(shell rm -rf deps.log temp.log )
touchlogs := $(shell touch temp.log )
openssl = 0
libverbs = 0
libcm = 0
iwarp_comp := 0
dist := 
DISTRO := 
ppc_dist :=
DEBUG := 0
vers := 2.12.0.3
pathssl := /usr/include/openssl/evp.h
pathverbs64 := /usr/lib64/libibverbs.so
pathverbs := /usr/lib/libibverbs.so
pathcm64 := /usr/lib64/librdmacm.so
pathcm := /usr/lib/librdmacm.so
pathcmu := /usr/lib/x86_64-linux-gnu/librdmacm.so
debDistros := ubuntu12u04 ubuntu12u042 ubuntu14u041 ubuntu14u042 ubuntu14u043 Debian
rpmgen := 0
UM_UNINST := 0
error_exit := 1
libs_ofed := 0
ipv6_enable := 0
ipv6_chk := $(shell ls /proc/sys/net/)
moddir = $(shell echo "/lib/modules/`uname -r`/." ;)
udp_libs := libcxgb4_udp:libcxgb4_sock:libcxgb4_udp_debug:libcxgb4_sock_debug
installprecheck := 0
firm_config := UNIFIED_WIRE
debug_patch := 1
kerFlag := 0
UM_VERSION:=2.4-78
NULL_OUT := /dev/null
AUTO_INST := 0
AUTO_BIN := $(shell which autoconf 2>/dev/null  )
TOOLS_UNINST := 0
ifneq ($(AUTO_BIN), ) 
  AUTOCONF_VER := $(strip $(shell $(AUTO_BIN) --version | head -1 | awk '{print $$4}' 2>/dev/null ))
  AU_MAJVER := $(word 1, $(subst ., ,$(AUTOCONF_VER)))
  AU_MINVER := $(word 2, $(subst ., ,$(AUTOCONF_VER)))
  AUTO_INST := $(shell [ \( $(AU_MINVER) -lt 2  -a  $(AU_MAJVER) -lt 63 \) ] && echo 1 || echo 0 ; )
else
  AUTO_INST := 1
endif
ifdef BENCHMARKS
    BENCHMARK_FLAG := $(BENCHMARKS)
else
    BENCHMARK_FLAG := 0
endif

ifdef SKIP_RPM
    NORPMKERNELFLAG := $(SKIP_RPM)
endif
ifndef NORPMKERNELFLAG
    NORPMKERNELFLAG := 0
endif
ifdef INSTALL_UM
    UM_INST := $(INSTALL_UM)
else
    UM_INST := 1
endif
ifndef dcbx
    dcbx := 0
endif
ifndef ipv6_disable
    ipv6_disable := 0
endif
ifeq ($(ipv6_disable),1)
    ipv6_enable := 0
else
    ifeq ($(filter ipv6,$(ipv6_chk)),ipv6)
        ipv6_enable := 1
    endif
endif
ifeq ($(dcbx),1)
    enable_dcb := 1
else
    enable_dcb := 0
endif
ifdef CONF
    ifeq ($(CONF),T4_CONF_UWIRE)
        CONF := UNIFIED_WIRE
    endif 
    ifeq ($(CONF),T4_CONF_HCTOE)
        CONF := HIGH_CAPACITY_TOE
    endif 
    ifeq ($(CONF),T4_CONF_LL)
        CONF := LOW_LATENCY
    endif 
    ifeq ($(CONF),T4_CONF_HCRDMA)
        CONF := HIGH_CAPACITY_RDMA
    endif 
    ifeq ($(CONF),T4_CONF_USO)
        CONF := UDP_OFFLOAD
    endif 
endif
ifeq ($(filter $(MAKECMDGOALS),clean prep distclean rpmclean help list_kernels), )
    k := 0
    chk := $(strip $(shell ${pwd}/scripts/chk_disk.sh))
    #$(info $(chk) )
    k := $(firstword $(chk))
    #$(info $(k))
    ifneq ($(k),0)
        $(error Requires $(word 1,$(chk)) MB more disk space in $(word 2,$(chk)) )
    endif
endif
 
r6x_kernels := 2.6.32-279.el6 2.6.32-358.el6 2.6.32-431.el6 2.6.32-504.el6 2.6.32-573.el6
r7x_kernels := 3.10.0-123.el7 3.10.0-229.el7 3.10.0-229.el7.ppc64 3.10.0-229.ael7b.ppc64le 3.10.0-327.el7 3.10.0-327.el7.ppc64
s11sp1_kernel := 
s11x_kernels := 3.0.13-0.27 3.0.76-0.11 3.0.101-63-default
s12_kernel := 3.12.28-4 3.12.49-11
u1404x_kernels := 3.13.0-32-generic 3.16.0-30-generic
u14043_kernel := 3.19.0-25-generic
sw_kernels := 4.1
v3x_kernels := 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17 3.18
ex_kernels := 3.4

supported_kernels := $(r6x_kernels) $(r7x_kernels) $(s11sp1_kernel) $(s11x_kernels) $(s12_kernel) $(u1404x_kernels) $(u14043_kernel) $(ex_kernels) $(v3x_kernels) $(sw_kernels) 
 
supported_config := UNIFIED_WIRE HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY UDP_OFFLOAD T5_WIRE_DIRECT_LATENCY \
                    HIGH_CAPACITY_WD T5_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE MEMORY_FREE T4_UN
# Checking whether kernel we are running on is supported or not.
ifndef UNAME_R
  UNAME_R := $(shell uname -r)
endif   
$(info Building for kernel $(UNAME_R))
error_exit := $(foreach var,$(supported_kernels),$(if $(findstring $(var),$(UNAME_R)),0))
ifeq ($(strip $(error_exit)),)
    $(info Error: The kernel version ${UNAME_R} is not supported. Refer to README for supported kernel versions or run make list_kernels.)
    $(info For building drivers for updated kernels, run make UNAME_R=<base_kernel_versions>. The base kernel version can be one of the following.)
    $(info List of supported kernel Versions)
    $(foreach var,$(supported_kernels),$(info $(var)))
    $(error )
endif
export UNAME_R
export BENCHMARK_FLAG

#Determine which OS we are running on.
os_kernel_matrix = 2.6.18-128.el5|RHEL5.3|rhel5u3 \
                   2.6.18-164.el5|RHEL5.4|rhel5u4 \
                   2.6.18-194.el5|RHEL5.5|rhel5u5 \
                   2.6.18-238.el5|RHEL5.6|rhel5u6 \
                   2.6.18-274.el5|RHEL5.7|rhel5u7 \
                   2.6.18-308.el5|RHEL5.8|rhel5u8 \
                   2.6.18-348.el5|RHEL5.9|rhel5u9 \
                   2.6.18-371.el5|RHEL5.10|rhel5u10 \
                   2.6.18-398.el5|RHEL5.11|rhel5u11 \
                   2.6.32-71.el6|RHEL6.0|rhel6 \
                   2.6.32-131.0.15.el6|RHEL6.1|rhel6u1 \
                   2.6.32-220.el6|RHEL6.2|rhel6u2 \
                   2.6.32-279.el6|RHEL6.3|rhel6u3 \
                   2.6.32-358.el6|RHEL6.4|rhel6u4 \
                   2.6.32-431.el6|RHEL6.5|rhel6u5 \
                   2.6.32-504.el6|RHEL6.6|rhel6u6 \
                   2.6.32-573.el6|RHEL6.7|rhel6u7 \
                   3.10.0-123.el7|RHEL7.0|rhel7 \
                   3.10.0-229|RHEL7.1|rhel7u1 \
                   3.10.0-327.el7|RHEL7.2|rhel7u2 \
                   2.6.16.60-0.54.5|SLES10.3|sles10sp3 \
                   2.6.27.19-5|SLES11|sles11 \
                   2.6.32.12|SLES11sp1|sles11sp1 \
                   3.0.13|SLES11sp2|sles11sp2 \
                   3.0.76|SLES11sp3|sles11sp3 \
                   3.0.101|SLES11sp4|sles11sp4 \
                   3.12.28-4|SLES12|sles12 \
                   3.12.49-11|SLES12sp1|sles12sp1 \
                   2.6.33.3-85.fc|fedora13|fedora13 \
                   2.6.35.6-45.fc|fedora14|fedora14 \
                   3.2.0-23-generic|ubuntu-12.04|ubuntu12u04 \
                   3.5.0-23-generic|ubuntu-12.04.2|ubuntu12u042 \
                   3.13.0-32-generic|ubuntu-14.04.1|ubuntu14u041 \
                   3.16.0-30-generic|ubuntu-14.04.2|ubuntu14u042 \
                   3.19.0-25-generic|ubuntu-14.04.3|ubuntu14u043 \
                   2.6.34|2.6.34|kernel26u34 \
                   2.6.35|2.6.35|kernel26u35 \
                   2.6.36|2.6.36|kernel26u36 \
                   2.6.37|2.6.37|kernel26u37 \
                   2.6.39|2.6.39|kernel26u39 \
                   3.16|3.16|kernel3u16 \
                   3.18|3.18|kernel3u18 \
                   3.17|3.17|kernel3u17 \
                   3.13|3.13|kernel3u13 \
                   3.12|3.12|kernel3u12 \
                   3.11|3.11|kernel3u11 \
                   3.10|3.10|kernel3u10 \
                   3.9|3.9|kernel3u9 \
                   3.8|3.8|kernel3u8 \
                   3.7|3.7|kernel3u7 \
                   3.6|3.6|kernel3u6 \
                   3.5|3.5|kernel3u5 \
                   3.4|3.4|kernel3u4 \
                   3.1|3.1|kernel3u1 \
                   4.1|4.1|kernel4u1 \
                   2.6.16.60-0.21|SLES10.2|sles10sp2

KEDISTRO := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 1,\
                                              $(subst |, ,$(entry))))))
KEDISTRO := $(firstword $(KEDISTRO))
DISTRO := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 2,\
                                              $(subst |, ,$(entry))))))
dist := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 3,\
                                              $(subst |, ,$(entry))))))
DISTRO := $(firstword $(DISTRO))
dist := $(firstword $(dist))
kdist := $(DISTRO)
isKernel := $(firstword $(subst l,l ,$(dist)))
ifeq ($(isKernel),kernel)
  kerFlag := 1
  out := $(shell rpm -qf /etc/issue 2>&1 > /dev/null ; echo $$? )
  ifeq ($(out),0)
  distName := $(shell rpm -qf /etc/issue 2>/dev/null )
   ifdef distName
    checkos := $(findstring red,$(distName))
    ifdef checkos
      checkos := red
      distVersion := $(shell cat /etc/issue | grep -i Server | head -1 | awk '{print $$7}')
    else
      checkos := $(findstring centos,$(distName))
      ifdef checkos
        checkos := red
        distVersion := $(shell cat /etc/issue | head -1 | awk '{print $$3}')
      else
        checkos := $(findstring sles, $(distName))
        ifdef checkos
          checkos := sles
          distVersion := $(shell cat /etc/issue | grep -i Server | head -1 | awk '{print $$7 $$8}')
          NORPMKERNELFLAG := 1
        else
          checkos := $(findstring fedora, $(distName))
          ifdef checkos
            checkos := fedora
            distVersion := $(shell cat /etc/issue | head -1 | awk '{print $$3}') 
          endif
        endif 
      endif               
     endif
   endif
  else
    distName := $(shell cat /etc/issue | head -1 )
    checkos := $(findstring Ubuntu, $(distName))
    ifdef checkos
      checkos := ubuntu
      distVersion := 
      DEBIAN := 1
    else
      checkos := $(findstring Debian, $(distName))
      ifdef checkos
          checkos := Debian
          distVersion := 
          DEBIAN := 1
          PDEB := 1
      endif
    endif
  endif

  ifeq ($(checkos),red)
   distC := RHEL
   kdist := $(distC)$(firstword $(distVersion))
  endif
  ifeq ($(checkos),sles)
    distpostfix := $(firstword $(distVersion))
    distpostfix := $(shell tr '[:upper:]' '[:lower:]' <<< $(distpostfix))
    ifeq ($(findstring 12,$(distVersion)),12)
      kdist := SLES12
    else
      kdist := SLES11
    endif
    kdist := $(kdist)$(distpostfix)
  endif 
  ifeq ($(checkos),fedora)
    distC := fedora
    kdist := $(distC)$(firstword $(distVersion))
  endif
  ifeq ($(checkos),ubuntu)
    distC := ubuntu-
    kdist := $(distC)$(firstword $(distVersion))
  endif

endif

ifneq ($(filter ${dist},$(debDistros)), )
    DEBIAN := 1
endif

ifneq ($(filter $(DISTRO),$(sw_kernels)), )
  patchSrc := 0
else
  patchSrc := 1
endif

ifneq ($(filter $(kdist),RHEL5.3 RHEL5.4 RHEL5.5 RHEL5.6 RHEL6.1 RHEL6.2 RHEL6.0 fedora13 fedora14 SLES11), )
  kdist_lib := 
else
  kdist_lib :=
endif

cxgbtool_msg := cxgbtool/cop
ifneq ($(filter $(arch),ppc64 ppc64le),)
  ppc_dist := $(dist)
  udp_libs := 
  dcbx := 0
  enable_dcb := 0
  cxgbtool_msg := cxgbtool    
endif

ifeq ($(DEBUG),1)
  $(info DISTRO : $(DISTRO))
  $(info DIST : $(dist))
endif
ifndef CONF
  CONF := UNIFIED_WIRE
endif
ifneq ($(findstring udp_offload,$(MAKECMDGOALS)),)
  CONF := UDP_OFFLOAD
endif
error_exit = $(foreach var,$(supported_config),$(if $(findstring $(var),$(CONF)),0))
ifeq ($(strip $(error_exit)),)
    $(info Error: Unknown config option ${CONF}.)
    $(info List of supported configurations: )
    $(foreach var,$(filter-out T4_UN, ${supported_config}),$(info $(var)))
    $(error )
endif

ifeq ($(KDIR),)
  ifeq ($(KSRC),)
    ifneq ($(KOBJ),)
      $(warning When using KOBJ=<path>, the KSRC=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: kernel source path not specified)
    endif
  else
    ifeq ($(KOBJ),)
      $(warning When using KSRC=<path>, the KOBJ=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: KOBJ path not specified)
    endif
  endif
else
  override KSRC := $(KDIR)
  override KOBJ := $(KDIR)
endif

ifeq ($(wildcard $(pathssl)),)
  openssl := 0
else
  openssl := 1
endif
ifneq ($(filter $(arch),x86_64 ppc64 ppc64le),)
  ifeq ($(wildcard $(pathverbs64)),)
      libverbs := 0
  else
      libverbs := 1
  endif 
  ifeq ($(wildcard $(pathcm64)),)
      libcm := 0
  else 
      libcm := 1
  endif 
else 
  ifeq ($(wildcard $(pathverbs)),)
      libverbs := 0
  else
      libverbs := 1
  endif 
  ifeq ($(wildcard $(pathcm)),)
      libcm := 0
  else 
      libcm := 1
  endif 
endif
ifeq ($(DEBIAN),1)
  out := $(shell find  debrules/ -name control -type f ; ) 
  $(foreach cfile,$(out),$(shell sed -i s"/Architecture: .*/Architecture: `dpkg --print-architecture`/"g ${cfile}))
endif
ifneq ($(DEBIAN),1)
    ifeq (${libverbs},1)
        verbs_rpm := $(shell rpm -qa | grep libibverbs-devel -c )
        ifeq ($(verbs_rpm),0)
            libverbs := 0
        endif
    endif
    ifeq (${libcm},1)
        cm_rpm := $(shell rpm -qa | grep librdmacm-devel -c )
        ifeq ($(cm_rpm),0)
            libcm := 0
        endif
    endif
endif
ifeq ($(DEBIAN),1)
  # set NORPMKERNELFLAG if Ubuntu or Kernel compiled on SLES.
  ifeq ($(wildcard $(pathverbs)),)
      libverbs := 0
  else
      libverbs := 1
  endif
  ifeq ($(wildcard $(pathcmu)),)
      libcm := 0
      ifeq  ($(wildcard $(pathcm)),)
          libcm := 0
      else
          libcm := 1 
      endif
  else
      libcm := 1
  endif
endif

# Only if KSRC/KOBJ were not defined on the command line.
ifeq ($(DEBIAN),1)
  ifneq ($(PDEB),1)
    KSRC ?= $(wildcard /lib/modules/$(shell uname -r)/build)
  endif
endif
KSRC ?= $(wildcard /lib/modules/$(shell uname -r)/source)
KOBJ ?= $(wildcard /lib/modules/$(shell uname -r)/build)

export KDIR
export KSRC
export KOBJ
export OFA_DIR
export logpath
export rhel6
export sles11
export libcm
export libverbs
export CONF
export cxgbtool_msg
export DEBIAN

uwire_supports  := bonding nic nic_offload toe iwarp vnic sniffer fcoe_full_offload_initiator \
                  iscsi_pdu_target iscsi_pdu_initiator fcoe_pdu_offload_target \
                  tools bypass toe_ipv4 libibverbs_rpm librdmacm_rpm removeallPrevious \
                  wdtoe wdtoe_libs wdtoe_wdudp rdma_block_device autoconf_install
hctoe_supports := bonding nic nic_offload toe tools toe_ipv4  
hcrdma_supports := bonding nic nic_offload toe iwarp tools sniffer toe_ipv4 rdma_block_device
ll_supports := bonding nic nic_offload toe iwarp tools toe_ipv4 sniffer wdtoe wdtoe_libs wdtoe_wdudp rdma_block_device
un_supports := removeall uninstall_all
#nic toe ipv6 iwarp bonding vnic sniffer fcoe_full_offload_initiator\
              iscsi_pdu_target iscsi_pdu_initiator libs tools bypass fcoe_full_offload_target uninstall_all
uso_supports := bonding nic nic_offload udp_offload tools 
edc_only_supports := nic nic_offload toe iwarp tools wdtoe wdtoe_libs wdtoe_wdudp rdma_block_device
t5_hcllwd_supports := nic toe nic_offload iwarp tools wdtoe wdtoe_libs wdtoe_wdudp rdma_block_device
hashfilter_supports := nic_offload tools
rdmaperf_supports := nic nic_offload toe iwarp tools toe_ipv4 rdma_block_device
iscsiperf_supports := nic nic_offload toe bonding iscsi_pdu_target iscsi_pdu_initiator tools
memfree_supports := nic nic_offload toe iwarp tools toe_ipv4

USER_MAKECMDGOALS := $(MAKECMDGOALS)
k=$(words $(MAKECMDGOALS))
j=0
ifeq ($(MAKELEVEL),0)
    ifeq ($(k),0)
        ifeq ($(CONF),UNIFIED_WIRE)
            MAKECMDGOALS = $(filter-out  nic bypass fcoe_pdu_offload_target toe_ipv4 nic_ipv4 wdtoe wdtoe_libs wdtoe_wdudp libibverbs_rpm librdmacm_rpm autoconf_install removeallPrevious, ${uwire_supports})
        endif
        ifeq ($(CONF),HIGH_CAPACITY_TOE)
           MAKECMDGOALS = $(filter-out nic bypass toe_ipv4 nic_ipv4 wdtoe wdtoe_libs wdtoe_wdudp ipv6, ${hctoe_supports} )
        endif
        ifeq ($(CONF),HIGH_CAPACITY_RDMA)
           MAKECMDGOALS = $(filter-out  nic toe_ipv4 nic_ipv4 ipv6 wdtoe_wdudp, ${hcrdma_supports} )
        endif
        ifeq ($(CONF),RDMA_PERFORMANCE)
           MAKECMDGOALS = $(filter-out  nic toe_ipv4, ${rdmaperf_supports} )
        endif
        ifeq ($(CONF),LOW_LATENCY)
           MAKECMDGOALS = $(filter-out nic toe nic_offload toe_ipv4 nic_ipv4 ipv6 wdtoe_libs wdtoe_wdudp, ${ll_supports})
        endif
        ifeq ($(CONF),UDP_OFFLOAD)
           MAKECMDGOALS = $(filter-out nic toe_ipv4 nic_ipv4 wdtoe_wdudp, ${uso_supports})
        endif
        ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
           MAKECMDGOALS = $(filter-out nic toe nic_offload wdtoe_libs wdtoe_wdudp, ${edc_only_supports})
        endif
        ifeq ($(CONF),HIGH_CAPACITY_WD)
           MAKECMDGOALS = $(filter-out nic toe nic_offload wdtoe_libs wdtoe_wdudp, ${t5_hcllwd_supports})
        endif
        ifeq ($(CONF),T5_HASH_FILTER)
           MAKECMDGOALS = ${hashfilter_supports}
        endif
        ifeq ($(CONF),ISCSI_PERFORMANCE)
           MAKECMDGOALS = $(filter-out nic, ${iscsiperf_supports})
        endif
        ifeq ($(CONF),MEMORY_FREE)
           MAKECMDGOALS = $(filter-out nic toe_ipv4, ${memfree_supports})
        endif
    endif
    ifneq ($(filter $(MAKECMDGOALS),install rpm deb), )
        ifeq ($(CONF),UNIFIED_WIRE)
           GOALS := $(foreach goal,$(filter-out libibverbs_rpm librdmacm_rpm autoconf_install removeallPrevious, ${uwire_supports}),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_TOE)
           GOALS := $(foreach goal,$(hctoe_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_RDMA)
           GOALS := $(foreach goal,$(hcrdma_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),RDMA_PERFORMANCE)
           GOALS := $(foreach goal,$(rdmaperf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),LOW_LATENCY)
           GOALS := $(foreach goal,$(ll_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),UDP_OFFLOAD)
           GOALS := $(foreach goal,$(uso_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
           GOALS := $(foreach goal,$(edc_only_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_WD)
           GOALS := $(foreach goal,$(t5_hcllwd_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),T5_HASH_FILTER)
           GOALS := $(foreach goal,$(hashfilter_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),ISCSI_PERFORMANCE)
           GOALS := $(foreach goal,$(iscsiperf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),MEMORY_FREE)
           GOALS := $(foreach goal,$(memfree_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifneq ($(filter $(MAKECMDGOALS),rpm deb), )
             ifneq ($(filter $(CONF),LOW_LATENCY T5_WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD), )
                 #ifneq ($(filter $(dist),ubuntu12u04 ubuntu12u042 kernel26u35), )
                 ifeq (1,1) #Added this since wdtoe is not supported in any platforms
                     MAKECMDGOALS := $(filter-out nic_offload_$(MAKECMDGOALS) bonding_$(MAKECMDGOALS) wdtoe_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})	
                 else
                     MAKECMDGOALS := $(filter-out nic_offload_$(MAKECMDGOALS) bonding_$(MAKECMDGOALS) toe_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
                 endif	
             else
                 MAKECMDGOALS := $(filter-out nic_offload_$(MAKECMDGOALS) wdtoe_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
             endif
        else
             ifneq ($(filter $(CONF),LOW_LATENCY T5_WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD), )
                 #ifneq ($(filter $(dist),ubuntu12u04 ubuntu12u042 kernel26u35), )
                 ifeq (1,1) #Added this since wdtoe is not supported in any platforms
                     MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) nic_offload_$(MAKECMDGOALS) bonding_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) wdtoe_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
                 else
                     MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) nic_offload_$(MAKECMDGOALS) bonding_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) toe_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
                 endif
             else
                 MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) wdtoe_libs_$(MAKECMDGOALS) wdtoe_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
             endif
        endif
    endif
    ifneq ($(filter $(MAKECMDGOALS), uninstall), )
        GOALS := $(foreach goal,$(un_supports),$(goal))
        CONF := T4_UN
        MAKECMDGOALS := ${GOALS}
    endif
    ifneq ($(k),0)
        ifneq ($(filter $(CONF),UNIFIED_WIRE HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY T5_WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD UDP_OFFLOAD T5_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE MEMORY_FREE), )

            ifeq ($(CONF),UNIFIED_WIRE)
                conf_supports := $(uwire_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_TOE)
                conf_supports := $(hctoe_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_RDMA)
                conf_supports := $(hcrdma_supports)
            endif
            ifeq ($(CONF),RDMA_PERFORMANCE)
                conf_supports := $(rdmaperf_supports)
            endif
            ifeq ($(CONF),LOW_LATENCY)
                conf_supports := $(ll_supports)
            endif
            ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
                conf_supports := $(edc_only_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_WD)
                conf_supports := $(t5_hcllwd_supports)
            endif
            ifeq ($(CONF),UDP_OFFLOAD)
                conf_supports := $(uso_supports)
            endif
            ifeq ($(CONF),T5_HASH_FILTER)
                conf_supports := $(hashfilter_supports)
            endif
            ifeq ($(CONF),T4_CONF_TGT)
                conf_supports := $(tgt_uwire_supports)
            endif
            ifeq ($(CONF),ISCSI_PERFORMANCE)
                conf_supports := $(iscsiperf_supports)
            endif
            ifeq ($(CONF),MEMORY_FREE)
                conf_supports := $(memfree_supports)
            endif

            COMPILEGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(goal),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(COMPILEGOALS),$(MAKECMDGOALS))
            INSTALLGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _install, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(INSTALLGOALS),$(MAKECMDGOALS))
            UNINSTALLGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _uninstall, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(UNINSTALLGOALS),$(MAKECMDGOALS))
            RPMGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _rpm, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(RPMGOALS),$(MAKECMDGOALS))
            DEBGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _deb, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(DEBGOALS),$(MAKECMDGOALS))
        endif

        ifeq ($(CONF),T4_UN)
             UNINSTALLGOALS := $(MAKECMDGOALS)
             MAKECMDGOALS := $(filter-out $(UNINSTALLGOALS),$(MAKECMDGOALS))
        endif
    endif
    UNSUPPORTEDGOALS = ${MAKECMDGOALS}
    ifneq ($(words $(UNSUPPORTEDGOALS)),0)
        ifeq ($(filter $(UNSUPPORTEDGOALS),clean prep distclean rpmclean help list_kernels), )
              $(info The $(UNSUPPORTEDGOALS) is not supported with $(CONF) configuration.)
              $(info The following targets are supported with $(CONF))
              ifeq ($(CONF),UNIFIED_WIRE)
                conf_supports := $(filter-out autoconf_install,$(uwire_supports))
              endif
              ifeq ($(CONF),HIGH_CAPACITY_TOE)
                conf_supports := $(hctoe_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_RDMA)
                conf_supports := $(hcrdma_supports)
              endif
              ifeq ($(CONF),RDMA_PERFORMANCE)
                conf_supports := $(rdmaperf_supports)
              endif
              ifeq ($(CONF),LOW_LATENCY)
                conf_supports := $(ll_supports)
              endif
              ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
                conf_supports := $(edc_only_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_WD)
                conf_supports := $(t5_hcllwd_supports)
              endif
              ifeq ($(CONF),UDP_OFFLOAD)
                conf_supports := $(uso_supports)
              endif
              ifeq ($(CONF),T5_HASH_FILTER)
                conf_supports := $(hashfilter_supports)
              endif
              ifeq ($(CONF),T4_CONF_TGT)
                conf_supports := $(tgt_uwire_supports)
              endif
              ifeq ($(CONF),ISCSI_PERFORMANCE)
                conf_supports := $(iscsiperf_supports)
              endif
              ifeq ($(CONF),MEMORY_FREE)
                conf_supports := $(memfree_supports)
              endif
              ifeq ($(CONF),T5_HASH_FILTER)
                $(foreach var,$(conf_supports),$(info $(var)))
              else
                $(foreach var,$(conf_supports),$(if $(filter-out nic_offload,$(var)), $(info $(var))))
              endif
              $(error )
          endif
    endif
    MAKECMDGOALS = $(strip ${COMPILEGOALS}) $(strip ${INSTALLGOALS}) $(strip ${UNINSTALLGOALS}) $(strip ${RPMGOALS}) $(strip ${DEBGOALS})
    k=$(words $(MAKECMDGOALS))
endif

ifndef wdtoe_mode
  ifneq ($(findstring wdtoe,$(MAKECMDGOALS)),)
    wdtoe_mode=1
  else
    wdtoe_mode=0
  endif
endif

export wdtoe_mode

ifneq ($(filter nic_install nic_offload_install bonding_install toe_install,$(MAKECMDGOALS)),)
    $(shell rm -f /lib/modules/`uname -r`/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko;)
endif

ifneq ($(filter $(UNAME_R),3.6.11), )
    ifneq ($(filter $(kdist),RHEL6.6 RHEL6.5 RHEL6.4 RHEL6.3 RHEL6.1 RHEL6.2 RHEL6.0), )
        chfcoe_support:=
        ifneq ($(filter fcoe_pdu_offload_target  fcoe_pdu_offload_target_rpm  fcoe_pdu_offload_target_install,$(MAKECMDGOALS)), )
            enable_dcb=1
            po_fcoe=1
            CHFCOE_TARGET:=1
        endif
    else
        chfcoe_support:=kernel3u6
    endif
else
    chfcoe_support:=kernel3u6
endif
ifndef CHFCOE_TARGET
    CHFCOE_TARGET:=0
endif
export CHFCOE_TARGET
export po_fcoe

ifeq ($(inst),)
 inst := 0
endif
nic := 0
vnic := 0
toe := 0
iwarp_libs := 0
iwarp := 0
firmware := 0
ifneq ($(USER_MAKECMDGOALS),help)
  ifndef OFA_DIR
    mod_core := $(shell modinfo ib_core -F filename )
    found := $(findstring updates,$(mod_core))
    ifndef found
        found := $(findstring mlnx-ofa_kernel,$(mod_core))
    endif
    ifneq ($(filter $(found),updates mlnx-ofa_kernel), )
        kernel_ib := $(shell rpm -qa | grep kernel-ib-devel -c )
        compat_rdma := $(shell rpm -qa | grep compat-rdma-devel -c )
        mlnx_ofed := $(shell rpm -qa | grep mlnx-ofa_kernel-devel -c )
        is_ofed := $(shell echo "$(($((kernel_ib)) + $((compat_rdma)) + $((mlnx_ofed)) )) " )
        ifeq ($(kernel_ib),1)
            ofa_path_raw := $(shell rpm -ql kernel-ib-devel | grep -w Module.symvers ) 
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
        endif
        ifeq ($(compat_rdma),1)
            ofa_path_raw := $(shell rpm -ql compat-rdma-devel | grep -w Module.symvers )
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
        endif
        ifeq ($(mlnx_ofed),1)
            ofa_path_raw := $(shell rpm -ql mlnx-ofa_kernel-devel | grep -w Module.symvers )
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
            #$(info MLNX_OFED_PATH : $(OFA_DIR))
         endif
         ifeq ($(is_ofed),0)
	    $(warning ib_core modules exists in update path and kernel-ib-devel/compat-rdma-devel/mlnx-ofa_kernel-devel package is not installed)
         endif
         ifeq ($(OFA_DIR),)
            owner_rpm=$(shell rpm -qf $(mod_core))
            ofed_chk_inst:=$(owner_rpm)
            ofed_chk_inst:=$(subst ., ,$(ofed_chk_inst))
            #$(info $(ofed_chk_inst))
            #ifeq ($(findstring compat-rdma-3,$(ofed_chk_inst)),compat-rdma-3)
                #$(error Please Uninstall OFED-3.5 and Restart the Installation)
                #ofa_path_raw := $(shell rpm -ql compat-rdma-devel | grep -w Module.symvers )
                #ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
                #OFA_DIR := $(ofa_path_final)
                #libs_ofed := 1
            #endif
            ifneq ($(findstring ofed-kmp-default,$(owner_rpm)),ofed-kmp-default)
                $(error Provide OFA_DIR=<Path to OFED Source> to build/install the drivers)
            endif
         endif
    else 
       ifdef OFA_DIR
           OFA_DIR :=
       endif
    endif
  else
       libs_ofed := 1
  endif
endif

#List of all supported Makefile targets
is_bonding := 0
is_vnic := 0
is_toe := 0
is_wdtoe := 0
is_nic := 0
is_ipv6 := 0
is_iwarp := 0
is_wd_udp := 0
is_udp_offload := 0
is_bypass := 0
is_sniffer := 0
is_fcoe_full_offload_initiator := 0
is_iscsi_full_offload_initiator := 0
is_iscsi_pdu_target := 0
is_iscsi_pdu_initiator := 0
is_fcoe_pdu_offload_target := 0
# Below variables contains unsupported kernel for each of the above targets
is_bonding_kernel_unsupport := sles10sp3 sles10sp2 fedora13 fedora14 kernel26u39 kernel26u37 kernel26u36 \
                           kernel26u35 kernel26u34 $(ppc_dist) 
is_vnic_kernel_unsupport := kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 $(ppc_dist)
is_toe_kernel_unsupport := sles10sp2  
is_wdtoe_kernel_unsupport := sles10sp2 sles10sp3 sles11 fedora13 fedora14 kernel26u39 kernel26u37 kernel26u36 \
                             rhel5u3 rhel5u4 rhel5u5 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 rhel6 rhel6u1 \
                             rhel6u2 rhel6u3 rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel7 rhel7u1 rhel7u2 ubuntu12u04 ubuntu14u041 ubuntu12u042 ubuntu14u042 ubuntu14u043 \
                             kernel3u1 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel3u12 kernel4u1 \
                             kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 kernel3u6 $(ppc_dist)
is_nic_kernel_unsupport := 
is_ipv6_kernel_unsupport := kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 sles10sp3 sles10sp2 fedora13 fedora14 rhel5u3 
is_iwarp_kernel_unsupport := sles10sp2 sles10sp3  $(kdist_lib)
is_udp_offload_kernel_unsupport := sles10sp2 sles10sp3 kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 $(ppc_dist)
is_bypass_kernel_unsupport := sles10sp3 sles10sp2 $(ppc_dist)
is_sniffer_kernel_unsupport := sles10sp3 sles10sp2 ubuntu12u04 ubuntu12u042 kernel3u8 kernel3u9 kernel3u10 kernel3u11 \
                                     kernel3u12 kernel3u13 $(kdist_lib) $(ppc_dist)
is_fcoe_full_offload_initiator_kernel_unsupport := sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 \
                                               rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 ubuntu12u04 fedora13 ubuntu12u042 \
                                               fedora14 kernel3u1 kernel26u36 kernel26u37 kernel26u39 kernel3u8 kernel3u9 \
                                               kernel3u10 kernel3u11 kernel3u12 $(ppc_dist)
is_iscsi_full_offload_initiator_kernel_unsupport := sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 \
                                               rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 ubuntu12u04 fedora13 ubuntu12u042 \
                                               fedora14 kernel3u1 kernel26u36 kernel26u37 kernel26u39 kernel3u8 kernel3u9 \
                                               kernel3u10 kernel3u11 kernel3u12 $(ppc_dist)
is_iscsi_pdu_target_kernel_unsupport := sles10sp2 sles10sp3 fedora13 ubuntu12u042 
is_iscsi_pdu_initiator_kernel_unsupport := sles10sp2 sles10sp3 fedora13 fedora14 rhel5u3 ubuntu12u04 ubuntu12u042
is_fcoe_pdu_offload_target_kernel_unsupport := sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel7 rhel7u1 rhel7u2 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 $(chfcoe_support) $(ppc_dist)
is_wd_udp_kernel_unsupport := sles10sp2 sles10sp3 $(ppc_dist)
is_rdma_block_device_kernel_unsupport := sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel7 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 fedora14 kernel3u1 kernel26u35 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u6 sles11sp1 sles11sp2 sles11sp3 sles11sp4 ubuntu14u042 ubuntu14u043 $(chfcoe_support) $(ppc_dist)

#Set target availablity based on kernel version
all_special_target := is_nic is_vnic is_toe is_ipv6 is_bonding is_iwarp is_wd_udp is_udp_offload \
                     is_bypass is_sniffer is_fcoe_full_offload_initiator\
                     is_iscsi_pdu_target is_iscsi_pdu_initiator is_iscsi_full_offload_initiator \
                     is_fcoe_pdu_offload_target is_wdtoe is_rdma_block_device
define enable_tgt 
   override $(1) := 1
endef
define disable_tgt 
   override $(1) := 0
endef

$(foreach tgt,$(all_special_target), $(if $(filter $(dist), $(value $(tgt)_kernel_unsupport)),\
                                $(eval $(call disable_tgt,$(tgt))),$(eval $(call enable_tgt,$(tgt)))))
ifeq ($(DEBUG),1)
    $(info USER command : ${USER_MAKECMDGOALS})
    $(info MAKECMDGOALS : ${MAKECMDGOALS})
    $(info T4_CONFIGURATION : $(CONF))
    $(foreach tgt,$(all_special_target), $(info INFO : $(tgt) : $(value $(tgt))))
endif

bonding_mode := 0
ifeq ($(is_bonding),1)
 ifneq ($(filter bonding bonding_install bonding_deb bonding_rpm udp_offload udp_offload_rpm udp_offload_deb udp_offload_install,$(MAKECMDGOALS)), )
    override bonding_mode=1
    #MAKECMDGOALS := $(filter-out nic_install nic_offload_install toe_install toe_ipv4_install,$(MAKECMDGOALS))
    #MAKECMDGOALS += $(MAKECMDGOALS) nic_offload_install toe_install
 endif
endif
export bonding_mode

# The following block of code checks for libibverbs/librdmacm on system and install 
# libibverbs/librdmacm RPM if not present on machine.
ifneq ($(filter $(MAKECMDGOALS),iwarp libs sniffer iwarp_install libs_install \
                sniffer_install sniffer_rpm iwarp_rpm libs_rpm \
                wdtoe_wdudp wdtoe_wdudp_install wdtoe_wdudp_rpm rdma_block_device rdma_block_device_install), )
    iwarp_comp := 1
    ifeq ($(is_iwarp),1)
       ifeq ($(AUTO_INST),1)
          $(info Installing autoconf-2.63 )
          out := $(shell make --no-print-directory -C $(pwd) autoconf_install  )
        endif
        ifeq ($(DEBUG),1)
             $(info Found iWARP components in MAKECMDGOALS)
        endif
        ifeq ($(rpmgen),1)
             ifneq ($(filter 1,$(DEBIAN) $(NORPMKERNELFLAG)),1)
                 out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R})
                 out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R})
             endif
        endif
        ifeq ($(filter 0,$(libverbs) $(libcm)),0)
             libverbs = 0
             libcm = 0
        endif
        ifeq ($(libverbs),0)
             libs_ofed := 1
             ifeq ($(DEBIAN),1)
                 $(info libibverbs devel packages are not installed on system.)
                 $(info Installing libibverbs & libibverbs-devel on System)
                 out := $(shell make libibverbs_install UNAME_R=${UNAME_R} 2>/dev/null )
             else
                 $(info libibverbs-devel not installed on System)
                 $(info Installing libibverbs & libibverbs-devel on System)
                 out := $(shell rpm -e libibverbs1 --allmatches --nodeps &> /dev/null)
                 out := $(shell rpm -e libibverbs --allmatches --nodeps &> /dev/null)
                 ifeq ($(DEBUG),1)
                     out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R} DEBUG=1)
                 else
                     out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R})
                 endif
             endif
        endif
        ifeq ($(libcm),0)
             ifeq ($(DEBIAN),1)
                 $(info librdmacm devel packages are not installed on system.)
                 $(info Installing librdmacm & librdmacm-devel on System)
                 out := $(shell make  librdmacm_install UNAME_R=${UNAME_R} 2>/dev/null )
             else
                 $(info librdmacm-devel not installed on System)
                 $(info Installing librdmacm & librdmacm-devel on System)
                 out := $(shell rpm -e librdmacm1 --allmatches --nodeps &> /dev/null )
                 out := $(shell rpm -e librdmacm --allmatches --nodeps &> /dev/null )
                 ifeq ($(DEBUG),1)
                     out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R} DEBUG=1)
                 else
                     out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R}))
                 endif
             endif
        endif
    endif
endif
# The following block of code checks for a specific target avialablity and then changes
# the target prerequisites. If a target is not supported on a platform it clears the target
# prequisites.

ifeq ($(is_ipv6),0)
    ipv6_enable := 0
endif

ifeq ($(CONF),UNIFIED_WIRE)
    firm_config := UNIFIED_WIRE
endif
ifeq ($(CONF),LOW_LATENCY)
    firm_config := LOW_LATENCY_NETWORKING
endif
ifeq ($(CONF),HIGH_CAPACITY_RDMA)
    firm_config := HIGH_CAPACITY_RDMA
endif
ifeq ($(CONF),RDMA_PERFORMANCE)
    firm_config := RDMA_PERFORMANCE_CONFIGURATION
endif
ifeq ($(CONF),HIGH_CAPACITY_TOE)
    firm_config := HIGH_CAPACITY_TOE
endif
ifeq ($(CONF),ISCSI_PERFORMANCE)
    firm_config := ISCSI_PERFORMANCE_CONFIGURATION
endif
ifeq ($(CONF),MEMORY_FREE)
    firm_config := MEMORY_FREE_CONFIGURATION
endif
ifeq ($(CONF),UDP_OFFLOAD)
    firm_config := UDP_SEGEMENTATION_OFFLOAD
endif
ifeq ($(CONF),HIGH_CAPACITY_WD)
    firm_config := HIGH_CAPACITY_WD
endif
ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
    firm_config := T5_WIRE_DIRECT_LATENCY_CONFIGURATION
    $(shell echo -e "\n* T5_WIRE_DIRECT_LATENCY config tuning option is NOT SUPPORTED for Terminator 4 adapters" >> deps.log ; )
    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
endif
ifeq ($(CONF),T5_HASH_FILTER)
    firm_config := T5_HASH_FILTER_CONFIGURATION
    $(shell echo -e "\n* T5_HASH_FILTER config tuning option is NOT SUPPORTED for Terminator 4 adapters" >> deps.log ; )
    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
endif

ifeq ($(CONF),T4_UN)
    firm_config := UNINSTALL   
endif

ifneq ($(filter tools_install,$(MAKECMDGOALS)),)
  ifeq ($(words $(MAKECMDGOALS)),1)
    TOOLS_UNINST := 1
  endif
endif

depsout := $(shell ${pwd}/scripts/check_deps.sh $(iwarp_comp))
ifdef depsout
    build_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$1 }' | awk -F ':' '{ print $$1 }' ))
    ifneq ($(build_deps),0)
        build_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$1 }' | awk -F ':' '{ print $$2 }' ))
    endif
    rpm_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$2 }' | awk -F ':' '{ print $$1 }' ))
    ifneq ($(rpm_deps),0)
        rpm_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$2 }' | awk -F ':' '{ print $$2 }' ))
    endif
    install_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$3 }' | awk -F ':' '{ print $$1 }' ))
    ifneq ($(install_deps),0)
        install_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$3 }' | awk -F ':' '{ print $$2 }' ))
    endif
endif

ifeq ($(findstring install,$(MAKECMDGOALS)),install)
    buildprecheck=1
    rpmprecheck=1
    installprecheck=1
else
    ifeq ($(findstring rpm,$(MAKECMDGOALS)),rpm)
        buildprecheck=1
        rpmprecheck=1
    else
        buildprecheck=1
    endif
endif

ifeq ($(buildprecheck),1)
    ifneq ($(build_deps),0)
        $(info Following tools are required for compilation : $(build_deps_goals))
        $(error )
    endif
endif

ifeq ($(filter 1,$(NORPMKERNELFLAG) $(DEBIAN)), )
ifeq ($(buildprecheck),1)
    ifneq ($(rpm_deps),0)
        $(info Following tools are required for RPM generation : $(rpm_deps_goals))
        $(info Use SKIP_RPM=1 to continue installation without RPM generation)
        $(error )
    endif
endif
endif

ifeq ($(installprecheck),1)
    ifneq ($(install_deps),0)
        $(info Following tools are required for installation : $(install_deps_goals))
        $(error )
    endif
endif 

#ifneq ($(filter $(CONF),HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA), )
#    $(shell echo -e "* High Capacity Config tuning options are NOT SUPPORTED for Terminator 5 adapters" >> deps.log ; )
#    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
#endif

define get_prerequisites
	  $(strip $(shell ${pwd}/scripts/get_prerequisites.sh $(1) $(2) ${bonding_mode} ${NORPMKERNELFLAG} ))
endef

export is_bonding 
export is_vnic
export is_toe
export is_nic
export is_ipv6
export is_iwarp
export is_wd_udp
export is_udp_offload
export is_bypass
export is_sniffer
export is_fcoe_full_offload_initiator
export is_iscsi_pdu_target
export is_iscsi_pdu_initiator
export is_fcoe_pdu_offload_target
export dist
export DISTRO
export DEBUG
export vers
export libs_ofed
export kdist
export ipv6_enable
export dcb
export UM_VERSION
export enable_dcb
export ppc_dist

.DEFAULT:
	@echo "Build Targets:";\
	 echo ;\
	 echo " nic                                    - Build NIC drivers, disables all offload capablities.";\
	 echo " bonding                                - Build Bonding driver (offload).";\
	 echo " vnic                                   - Build vNIC driver.";\
	 echo " toe                                    - Build TOE driver (offload).";\
	 echo " toe_ipv4                               - Build TOE driver without ipv6 offload support (offload).";\
	 echo " wdtoe                                  - Build WD-TOE driver (offload).";\
	 echo " wdtoe_wdudp                            - Build WD-TOE driver (offload), WD-UDP Libraries and iWARP driver.";\
	 echo " iwarp                                  - Build iWARP driver and WD-UDP Libraries.";\
	 echo " udp_offload                            - Build UDP segmentaion offload & pacing drivers.";\
	 echo " bypass                                 - Build Bypass driver and tools.";\
	 echo " sniffer                                - Build Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_pdu_offload_target                - Build FCoE PDU offload target driver."; \
	 echo " fcoe_full_offload_initiator            - Build FCoE full offload initiator driver.";\
	 echo " iscsi_pdu_target                       - Build iSCSI-target driver, firmware and utilities.";\
	 echo " iscsi_pdu_initiator                    - Build open-iSCSI Data path accelerator driver.";\
	 echo " rdma_block_device                      - Build RDMA Block device driver.";\
	 echo " tools                                  - Build Chelsio utilities.";\
	 echo ;\
	 echo "Install Targets :";\
	 echo ;\
	 echo " install                                - Install all available drivers (offload).";\
	 echo " nic_install                            - Install NIC drivers and firmware, disables all offload capablities.";\
	 echo " bonding_install                        - Install Bonding driver and firmware (offload).";\
	 echo " vnic_install                           - Install vNIC driver and firmware.";\
	 echo " toe_install                            - Install TOE driver and firmware (offload).";\
	 echo " toe_ipv4_install                       - Install TOE driver without ipv6 offload support and firmware (offload).";\
	 echo " wdtoe_install                          - Install WD-TOE driver (offload) and firmware.";\
	 echo " wdtoe_wdudp_install                    - Install WD-TOE driver (offload), WD-UDP Libraries and iWARP driver.";\
	 echo " iwarp_install                          - Install iWARP driver, WD-UDP Libraries and firmware.";\
	 echo " udp_offload_install                    - Install UDP segmentaion offload & pacing driver.";\
	 echo " bypass_install                         - Install Bypass driver and tools.";\
	 echo " sniffer_install                        - Install Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_pdu_offload_target_install        - Install FCoE PDU offload target driver."; \
	 echo " fcoe_full_offload_initiator_install    - Install FCoE full offload initiator driver and firmware.";\
	 echo " iscsi_pdu_target_install               - Install iSCSI-target driver, firmware and utils.";\
	 echo " iscsi_pdu_initiator_install            - Install open-iSCSI, iSCSI-initiator, firmware and utils.";\
	 echo " rdma_block_device_install              - Install RDMA Block device driver.";\
	 echo " tools_install                          - Install Chelsio utilities.";\
	 echo ;\
	 echo "Uninstall Targets :";\
	 echo ;\
	 echo " uninstall                              - Uninstall all drivers (offload).";\
	 echo " nic_uninstall                          - Uninstall NIC driver and firmware.";\
	 echo " bonding_uninstall                      - Uninstall Bonding driver and firmware (offload).";\
	 echo " vnic_uninstall                         - Uninstall vNIC driver and firmware.";\
	 echo " toe_uninstall                          - Uninstall TOE driver and firmware (offload).";\
	 echo " toe_ipv4_uninstall                     - Uninstall TOE driver without ipv6 offload support and firmware (offload).";\
	 echo " wdtoe_uninstall                        - Uninstall WD-TOE driver (offload).";\
	 echo " wdtoe_wdudp_uninstall                  - Uninstall WD-TOE driver (offload), WD-UDP Libraries and iWARP driver.";\
	 echo " iwarp_uninstall                        - Uninstall iWARP driver, WD-UDP Libraries and firmware.";\
	 echo " udp_offload_uninstall                  - Uninstall UDP segmentaion offload & pacing driver.";\
	 echo " bypass_uninstall                       - Uninstall Bypass driver and tools.";\
	 echo " sniffer_uninstall                      - Uninstall Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_pdu_offload_target_uninstall      - Uninstall FCoE PDU offload target driver."; \
	 echo " fcoe_full_offload_initiator_uninstall  - Uninstall FCoE full offload initiator driver and firmware.";\
	 echo " iscsi_pdu_target_uninstall             - Uninstall iSCSI-target driver, firmware and utils.";\
	 echo " iscsi_pdu_initiator_uninstall          - Uninstall open-iSCSI, iSCSI-initiator, firmware and utils.";\
	 echo " rdma_block_device_uninstall            - Uninstall RDMA Block device driver.";\
	 echo " tools_uninstall                        - Uninstall Chelsio utilities.";\
	 echo ;\
	 if [ $(DEBIAN) == 1 ] ; then \
	    echo "DEB Targets :";\
	    echo ;\
	    echo " deb                                    - Generate DEB for all drivers (offload).";\
	    echo " nic_deb                                - Generate DEB for NIC driver and firmware.";\
	    echo " bonding_deb                            - Generate DEB for Bonding Driver (offload).";\
	    echo " vnic_deb                               - Generate DEB for vNIC driver and firmware.";\
	    echo " toe_deb                                - Generate DEB for TOE driver and firmware (offload).";\
	    echo " toe_ipv4_deb                           - Generate DEB for TOE driver without ipv6 offload support and firmware (offload).";\
	    echo " wdtoe_deb                              - Generate DEB for WD-TOE driver (offload) and firmware.";\
	    echo " wdtoe_wdudp_deb                        - Generate DEB for WD-TOE driver (offload), WD-UDP Libraries and iWARP driver.";\
	    echo " iwarp_deb                              - Generate DEB for iWARP driver, WD-UDP Libraries and firmware.";\
	    echo " udp_offload_deb                        - Generate DEB for UDP segmentaion offload & pacing  driver.";\
	    echo " bypass_deb                             - Generate DEB for Bypass driver and firmware.";\
	    echo " sniffer_deb                            - Generate DEB for Sniffer tracing & filtering tcpdump and iwarp driver.";\
	    echo " fcoe_pdu_offload_target_deb            - Generate DEB for FCoE PDU offload target driver."; \
	    echo " fcoe_full_offload_initiator_deb        - Generate DEB for full offload FCoE initiator driver and firmware.";\
	    echo " iscsi_pdu_target_deb                   - Generate DEB for iSCSI-target driver, firmware and utils.";\
	    echo " iscsi_pdu_initiator_deb                - Generate DEB for open-iSCSI, iSCSI-initiator, firmware and utils.";\
	    echo " rdma_block_device_deb                  - Generate DEB for RDMA Block device driver.";\
	    echo " tools_deb                              - Generate DEB for Chelsio utilities.";\
	 else \
	    echo "RPM Targets :";\
	    echo ;\
	    echo " rpm                                    - Generate RPM for all drivers (offload).";\
	    echo " nic_rpm                                - Generate RPM for NIC driver and firmware.";\
	    echo " bonding_rpm                            - Generate RPM for Bonding Driver (offload).";\
	    echo " vnic_rpm                               - Generate RPM for vNIC driver and firmware.";\
	    echo " toe_rpm                                - Generate RPM for TOE driver and firmware (offload).";\
	    echo " toe_ipv4_rpm                           - Generate RPM for TOE driver without ipv6 offload support and firmware (offload).";\
	    echo " wdtoe_rpm                              - Generate RPM for WD-TOE driver (offload) and firmware.";\
	    echo " wdtoe_wdudp_rpm                        - Generate RPM for WD-TOE driver (offload), WD-UDP Libraries and iWARP driver.";\
	    echo " iwarp_rpm                              - Generate RPM for iWARP driver, WD-UDP Libraries and firmware.";\
	    echo " udp_offload_rpm                        - Generate RPM for UDP segmentaion offload & pacing  driver.";\
	    echo " bypass_rpm                             - Generate RPM for Bypass driver and firmware.";\
	    echo " sniffer_rpm                            - Generate RPM for Sniffer tracing & filtering tcpdump and iwarp driver.";\
	    echo " fcoe_pdu_offload_target_rpm            - Generate RPM for FCoE PDU offload target driver."; \
	    echo " fcoe_full_offload_initiator_rpm        - Generate RPM for full offload FCoE initiator driver and firmware.";\
	    echo " iscsi_pdu_target_rpm                   - Generate RPM for iSCSI-target driver, firmware and utils.";\
	    echo " iscsi_pdu_initiator_rpm                - Generate RPM for open-iSCSI, iSCSI-initiator, firmware and utils.";\
	    echo " rdma_block_device_deb                  - Generate RPM for RDMA Block device driver.";\
	    echo " tools_rpm                              - Generate RPM for Chelsio utilities.";\
	 fi ;\
	 echo ;\
	 echo "Other Targets :" ;\
	 echo ;\
	 echo " clean                                  - Removes all generated files.";\
	 echo " distclean                              - Removes all generated files and rpms.";\
	 echo " help                                   - Display this message.";\
	 echo ;\
	 echo "Options: These are optional args";\
	 echo ;\
	 echo " OFA_DIR                                - OFA_DIR=<ofa_kernel path> Provide the ofa_kernel path";\
	 echo " KSRC                                   - KSRC=<kernel source path> Provide the kernel source path " ;\
	 echo "                                          Note: If the option is used KOBJ should also be provided " ;\
	 echo " KOBJ                                   - KOBJ=<kernel object path> Provide the kernel object path " ;\
	 echo "                                          Note: If the option is used KSRC should also be provided " ;\
	 echo " KDIR                                   - KDIR=<kernel directory path> Provide the kernel directory path " ;\
	 echo "                                          Note: Use this option if both KSRC,KOBJ are in the same path" ;\
	 echo " UNAME_R                                - UNAME_R=<kernel version> Provide the kernel version for desired target distro" ;\
	 echo "                                          Note: Use this option to build drivers for Distro kernel updates." ;\
	 echo "                                                Run make list_kernels to list all supported kernel versions." ;\
	 echo " CONF                                   - CONF=<T5/T4 configuration> Provide the T5/T4 configuration, available options are :";\
	 echo "                                                UNIFIED_WIRE, HIGH_CAPACITY_TOE, HIGH_CAPACITY_RDMA, LOW_LATENCY, UDP_OFFLOAD,";\
         echo "                                                T5_WIRE_DIRECT_LATENCY, HIGH_CAPACITY_WD, T5_HASH_FILTER" ;\
	 echo "                                                RDMA_PERFORMANCE, MEMORY_FREE, ISCSI_PERFORMANCE" ;\
	 echo " ipv6_disable                           - ipv6_disable=<1|0> 1 - Build all drivers without IPv6 support" ; \
	 echo "                                                             0 - Build all drivers with IPv6 support" ; \
	 echo " dcbx                                   - dcbx=<1|0> 1 - Build all drivers with DCBX support" ; \
         echo "                                                     0 - Build all drivers without DCBX support" ; \
	 echo " list_kernels                           - List all the supported kernels and valid arguments for UNAME_R options." ;\
	 echo " BENCHMARKS                             - BENCHMARKS=<1|0> 1 - Install Drivers with Benchmark tools" ; \
         echo "                                                           0 - Install Drivers without Benchmark tools" ;\
         echo "                                          Note: This Option can be used only with tools" ;\
	 echo " INSTALL_UM                             - INSTALL_UM=<1|0> 1 - Install UM with the tools" ; \
         echo "                                                           0 - Skip UM Installation" ; \
         echo " SKIP_RPM                               - SKIP_RPM=1 - Install driver binaries without generating RPM/DEB packages" ; \
	 echo; 

.PHONY: all	
all: $(MAKECMDGOALS)
	
.PHONY: list_kernels
list_kernels:
	$(info List of supported kernel Versions)
	$(foreach var,$(supported_kernels),$(info $(var)))
	@ echo


.PHONY: nic
nic:
ifeq ($(nic),0)
	@ if [ ! -d "build" ] ; then\
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_nic) -eq 1 ] && [ $(CONF) != "T5_HASH_FILTER" ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic ;\
	  else \
	      echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	      echo -e "Network(NIC)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
nic = 1
endif 

.PHONY: nic_offload
nic_offload:
ifeq ($(nic),1)
	@ if [ ! -d "build" ] ; then\
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_nic) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic_offload ;\
	  else \
	      echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	      echo -e "Network(NIC)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
nic = 2
endif 

.PHONY: nic_ipv4
nic_ipv4:
	@ if [ ! -d "build" ] ; then\
                $(MAKE) --no-print-directory prep;\
          fi ; \
          if [ $(is_nic) -eq 1 ] ; then \
              $(MAKE) --no-print-directory -C $(NwSrc) nic_ipv4 ;\
          else \
              echo -e "INFO : \t\tNIC [ Not supported ]" ; \
              echo -e "Network(NIC_IPV4)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
          fi;\
          $(call displaysummary,$(@),Build)

.PHONY: bonding
bonding:
	@ if [ ! -d "build" ] ; then\
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bonding) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) bonding ;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-offload\t\tbonding\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 

.PHONY: vnic
vnic:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_vnic) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) vnic ; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: toe
toe: $(strip $(call get_prerequisites,toe,${is_toe}))
ifeq ($(toe),0)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) toe ;\
	  if [ $(ipv6_enable) -eq 0 ] ; then \
	       echo -e "IPv6-offload\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-offload(TOE)\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
toe = 1
endif 

.PHONY: wdtoe
wdtoe: $(strip $(call get_prerequisites,wdtoe,${is_wdtoe}))
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) wdtoe ;\
	  else \
	       echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	       echo -e "WD-TOE\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: wdtoe_wdudp
wdtoe_wdudp: wdtoe iwarp
	@ $(call displaysummary,$(@),Build)

.PHONY: toe_ipv4
toe_ipv4:$(strip $(call get_prerequisites,toe_ipv4,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4 ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-offload(TOE)\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: ipv6
ipv6:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_ipv6) -eq 1 ] ; then \
		echo -e "INFO : \t\tipv6 " ;\
		echo -e "IPv6-offload\t\tipv6\t\tBuild\tSuccessful" >> temp.log ; \
	  else \
		echo -e "INFO : \t\tipv6 [ Not supported ]" ;\
		echo -e "IPv6-offload\t\tipv6\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: bypass
bypass:$(strip $(call get_prerequisites,bypass,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 @ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep;\
	   fi ; \
	 if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic_bypass ;\
	 else \
	     echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	     echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	 fi ; \
	 $(call displaysummary,$(@),Build)

.PHONY: iwarp
iwarp: $(strip $(call get_prerequisites,iwarp,${is_iwarp}))
ifeq ($(iwarp),0)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iwarp) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) iwarp ; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 
iwarp = 1
endif 

.PHONY: udp_offload
udp_offload:$(strip $(call get_prerequisites,udp_offload,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) udp_offload ; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 

.PHONY: fcoe_full_offload_initiator
fcoe_full_offload_initiator:$(strip $(call get_prerequisites,fcoe_full_offload_initiator,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: fcoe_pdu_offload_target
fcoe_pdu_offload_target:$(strip $(call get_prerequisites,fcoe_pdu_offload_target,${is_fcoe_pdu_offload_target}))
	@ if [ ! -d "build" ] ; then \
                $(MAKE) --no-print-directory prep CHFCOE_TARGET=1;\
          fi ; \
	  if [ $(is_fcoe_pdu_offload_target) -eq 1  ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) chfcoe ; \
	  else \
                echo -e "INFO : \t\tfcoe_pdu_offload_target  [ Not supported ]" ; \
                echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: iscsi_full_offload_initiator
iscsi_full_offload_initiator:$(strip $(call get_prerequisites,iscsi_full_offload_initiator,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Build)

.PHONY: fcoe_full_offload_target
fcoe_full_offload_target:nic_offload
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  elif [ $(shell echo ${UNAME_R} | grep 2.6.32.12 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  elif [ $(shell echo ${UNAME_R} | grep 2.6.32-71 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] ||\
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_target [ Not supported ]" ; \
		echo -e "FCoE(full-offload-target)\t\tcsioscst\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: iscsi_pdu_target
iscsi_pdu_target: $(strip $(call get_prerequisites,iscsi_pdu_target,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) iscsi_target ; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)


.PHONY: iscsi_pdu_initiator
iscsi_pdu_initiator:$(strip $(call get_prerequisites,iscsi_pdu_initiator,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tBuild\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) cxgbi ; \
	  else \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tBuild\tNot-supported" >> temp.log ; \
		echo -e "* iSCSI PDU initiator requires openssl-devel to be installed." >> deps.log ; \
		echo -e "  Please refer to README for the dependencies." >> deps.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)


.PHONY: libs
libs:
ifeq ($(iwarp_libs),0)
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	        $(call checklibibverbs,all,Build,,libcxgb4) \
	  else \
		echo -e "INFO : \t\tiwarp-libraries  [ Not supported ]" ; \
		echo -e "RDMA(iWARP-Lib)\t\tlibcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)
iwarp_libs = 1
endif 

.PHONY: sniffer
sniffer: $(strip $(call get_prerequisites,sniffer,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_sniffer) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(ToolSrc) sniffer ; \
	  else \
	        echo -e "INFO : \t\tsniffer-libraries  [ Not supported ]" ; \
	        echo -e "Sniffer\t\twd_tcpdump\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: rdma_block_device
rdma_block_device: $(strip $(call get_prerequisites,rdma_block_device,${is_rdma_block_device}))
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_rdma_block_device) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(NwSrc) rdma_block ; \
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
		echo -e "RDMA-Block-Device\t\tRDMA\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: tools
tools:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  $(MAKE) --no-print-directory -C $(ToolSrc) ;\
	  $(call displaysummary,$(@),Build)

.PHONY: ba_tools
ba_tools:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	       $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools ;\
	  else \
	       echo -e "Bypass_tools\t\tba_*\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Build)
	

.PHONY: install
install: $(MAKECMDGOALS)

.PHONY: nic_install
nic_install:$(strip $(call get_prerequisites,nic_install,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	fi ;
	@ if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	if [ $(is_nic) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) nic_install ;\
	          $(call copyconfigfile) \
	     else \
		  ( $(call installdrvrpm,nic) )  && \
	          ( $(call copyconfigfile) )  &&  ( $(call logs,Network(NIC),cxgb4,Install ))  \
	          || $(call logtemp,Network(NIC),cxgb4,Install) \
	     fi;\
	else \
	    echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	    echo -e "Network(NIC)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	fi;\
	$(call displaysummary,$(@),Install) 

.PHONY: nic_offload_install
nic_offload_install:$(strip $(call get_prerequisites,nic_offload_install,${is_nic}))
ifeq ($(nic),2)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif

	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	fi ; \
	if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	if [ $(is_nic) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) nic_offload_install ;\
	         $(call copyconfigfile) \
	     else \
	         ( $(call installdrvrpm,nic_offload) ) && \
	         ( $(call copyconfigfile) ) &&  ( $(call logs,Network(NIC),cxgb4,Install ))  \
	         || $(call logtemp,Network(NIC),cxgb4,Install) \
	     fi;\
	else \
	    echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	    echo -e "Network(NIC)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	fi;\
	$(call displaysummary,$(@),Install) 
nic = 3
endif

.PHONY: nic_ipv4_install
nic_ipv4_install:$(strip $(call get_prerequisites,nic_ipv4_install,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
        fi ; \
        if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
             rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
        fi ; \
        if [ $(is_nic) -eq 1 ] ; then \
             if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                 $(MAKE) --no-print-directory -C $(NwSrc) nic_ipv4_install ;\
                 $(call copyconfigfile) \
             else \
                 ( $(call installdrvrpm,nic_offload) ) && \
                 ( $(call copyconfigfile) ) &&  ( $(call logs,Network(NIC_IPV4),cxgb4,Install ))  \
                 || $(call logtemp,Network(NIC_IPV4),cxgb4,Install) \
             fi;\
        else \
            echo -e "INFO : \t\tNIC [ Not supported ]" ; \
            echo -e "Network(NIC_IPV4)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
        fi;\
        $(call displaysummary,$(@),Install)

.PHONY: bonding_install
bonding_install:$(strip $(call get_prerequisites,bonding_install,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then\
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bonding) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) bonding_install ;\
		  $(call copyconfigfile) \
	     else \
	         ( $(call installdrvrpm,bonding) ) && \
	         ( $(call logs,Bonding-offload,bonding,Install)) \
	         || $(call logtemp,Bonding-offload,bonding,Install) \
	     fi;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-offload\t\tbonding\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: vnic_install
vnic_install:$(strip $(call get_prerequisites,vnic_install,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_vnic) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) vnic_install ;\
	          $(call copyconfigfile) \
	     else \
	       ( $(call installdrvrpm,vnic) ) && ( $(call logs,SR-IOV_networking(vNIC),cxgb4vf,Install) ) \
	       || ( $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Install) )\
	    fi;\
	  else \
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: toe_install
toe_install: $(strip $(call get_prerequisites,toe_install,${is_toe}))
ifeq ($(toe),1)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) toe_install ;\
		  $(call copyconfigfile) \
	     else\
                  if [ $(ipv6_enable) -eq 0 ] ; then \
	              ( $(call installdrvrpm,toe) ) && ( $(call logs,Network-offload(TOE),t4_tom,Install) \
		      echo -e "IPv6-offload\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
                      if [ $(is_udp_offload) -eq 1 ] ; then \
			 $(call logs,Udp-offload,t4_tom,Install) \
		      fi ; ) \
	              || ( $(call logtemp,Network-offload(TOE),t4_tom,Install) )\
		  else \
                      ( $(call installdrvrpm,toe) ) && ( $(call logs,Network-offload(TOE),t4_tom,Install) \
			if [ $(is_udp_offload) -eq 1 ] ; then \
	                      $(call logs,UDP-offload,t4_tom,Install) \
			fi ; \
			$(call logs,IPv6-offload,t4_tom,Install) ) \
                      || ( $(call logtemp,Network-offload(TOE),t4_tom,Install) )\
		  fi;\
	     fi;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-offload(TOE)\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)
toe = 2
endif 

.PHONY: wdtoe_install
wdtoe_install: $(strip $(call get_prerequisites,wdtoe_install,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) wdtoe_install ;\
		  $(call copyconfigfile) \
	       else\
	          ( $(call installdrvrpm,wdtoe) ) && ( $(call logs,WD-TOE,t4_tom,Install) )\
	          || ( $(call logtemp,WD-TOE,t4_tom,Install) )\
	       fi;\
	  else \
	       echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	       echo -e "WD-TOE\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: wdtoe_wdudp_install
wdtoe_wdudp_install: removeallPrevious wdtoe_install iwarp_install
	@ $(call displaysummary,$(@),Install)

.PHONY: wdtoe_libs_install
wdtoe_libs_install: $(strip $(call get_prerequisites,wdtoe_libs_install,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	      $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                 $(call checklibibverbs,wdtoe_lib_install,Install,wdtoe-Libraries,libwdtoe) \
	     else\
		  ( $(call installdrvrpm,wdtoe_lib) ) && ( $(call logs,Lib-WD-TOE,libwdtoe,Install) )\
	          || ( $(call logtemp,Lib-WD-TOE,libwdtoe,Install) )\
	     fi;\
	  else \
	       echo -e "INFO : \t\tLib WD-TOE [ Not supported ]" ; \
	       echo -e "Lib-WD-TOE\t\tlibwdtoe\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)


.PHONY: toe_ipv4_install
toe_ipv4_install: $(strip $(call get_prerequisites,toe_ipv4_install,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		 $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4_install ;\
	     else \
	          ( $(call installdrvrpm,toe_ipv4) ) &&  ( $(call logs,Network-offload(TOE),t4_tom,Install) $(call logs,Udp_offload,t4_tom,Install) \
	        ) || ( $(call logtemp,Network-offload(TOE),t4_tom,Install) )\
	     fi;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-offload(TOE)\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: ipv6_install
ipv6_install: $(strip $(call get_prerequisites,ipv6_install,${is_ipv6}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv6_install ;\
	      else\
		echo "Install IPv6"
	      fi;\
	  else  \
		echo -e "INFO : \t\tipv6 " ; \
	  fi; \
	  $(call displaysummary,$(@),Install)

.PHONY: bypass_install
bypass_install: $(strip $(call get_prerequisites,bypass_install,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 @ if [ ! -d "build" ] ; then\
	        $(MAKE) --no-print-directory prep;\
	   fi ; \
	if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) nic_bypass_install ;\
		 $(call copyconfigfile) \
	     else\
	         ( $(call installdrvrpm,bypass) ) && ( $(call logs,Network-Offload(Bypass),cxgb4,Install) \
	      )  || ( $(call logtemp,Network-Offload(Bypass),cxgb4,Install) )\
	     fi;\
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call copyconfigfile) \
	  $(call displaysummary,$(@),Install)

.PHONY: iwarp_install
iwarp_install: $(strip $(call get_prerequisites,iwarp_install,${is_iwarp}))
ifeq ($(iwarp),1)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;\
	  if [ $(is_iwarp) -eq 1 ] ; then \
	        if [ -f /lib/modules/$(shell uname -r)/updates/drivers/infiniband/hw/cxgb4/iw_cxgb4.ko ] ; then \
	              rm -f /lib/modules/$(shell uname -r)/updates/drivers/infiniband/hw/cxgb4/iw_cxgb4.ko ;\
	        fi ; \
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		    $(MAKE) --no-print-directory -C $(NwSrc) iwarp_install; \
		    $(call copyconfigfile) \
		else \
		   $(call libcxgb4_cleanup) \
	           ( ( $(call installdrvrpm,iwarp) ) && ( $(call logs,RDMA(iWARP),iw_cxgb4,Install) )\
	           && ( $(call logs,iWARP-lib,libcxgb4,Install) ) && ( \
	           if [ $(is_udp_offload) -eq 1 ] ; then \
	               $(call logs,WD-UDP,libcxgb4_sock,Install) \
	           fi ; ) )\
	           || ( ( $(call logtemp,RDMA(iWARP),iw_cxgb4,Install) ) && ( $(call logtemp,iWARP-lib,libcxgb4,Install) )\
	           && ( $(call logtemp,WD-UDP,libcxgb4_sock,Install) ))\
	        fi;\
	        if [ ! -f /etc/udev/rules.d/90-rdma.rules ] || [ ! -f  /etc/udev/rules.d/90-ib.rules ]; then \
	             cp build/tools/90-rdma.rules /etc/udev/rules.d/ ;\
	        fi ; \
	       $(call installrdmatools) \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install) 
iwarp = 2
endif

.PHONY: udp_offload_install
udp_offload_install:$(strip $(call get_prerequisites,udp_offload_install,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) udp_offload_install ; \
		 $(call copyconfigfile) \
	     else\
		 ( $(call installdrvrpm,udp_offload) ) && ( $(call logs,UDP-Offload,t4_tom,Install) \
		  if [ $(ipv6_enable) -eq 1 ] ; then \
			$(call logs,IPv6-offload,t4_tom,Install) \
		  fi ; )\
	         || ( $(call logtemp,UDP-Offload,t4_tom,Install) )\
	     fi;\
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Install) 

.PHONY: sniffer_install
sniffer_install:$(strip $(call get_prerequisites,sniffer_install,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_sniffer) -eq 1 ] ; then \
		if [ ${NORPMKERNELFLAG} == 1 ] ; then \
			$(MAKE) --no-print-directory -C $(ToolSrc) sniffer_install ; \
			$(call copyconfigfile) \
		else \
			( $(call installdrvrpm,sniffer) ) &&  \
		        ( $(call logs,Sniffer,wd_tcpdump,Install) ) || \
	        	( $(call logtemp,Sniffer,wd_tcpdump,Install) )\
		fi ; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: fcoe_full_offload_initiator_install
fcoe_full_offload_initiator_install:$(strip $(call get_prerequisites,fcoe_full_offload_initiator_install,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
          	if [ ${NORPMKERNELFLAG} == 1 ] ; then \
          		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_install ; \
			$(call copyconfigfile) \
          	else \
			( $(call installdrvrpm,fcoe_full_offload_initiator) ) && \
			( $(call logs,FCoE(full-offload-initiator),csiostor,Install) ) || \
		        ( $(call logtemp,FCoE(full-offload-initiator),csiostor,Install) )\
		fi ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: iscsi_full_offload_initiator_install
iscsi_full_offload_initiator_install:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_install,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Install)

.PHONY: fcoe_full_offload_target_install
fcoe_full_offload_target_install:nic_offload_install
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  elif [ $(sles11) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  elif [ $(rhel6) ]  || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_target [ Not supported ]" ; \
		echo -e "FCoE(full-offload-target)\t\tcsioscst\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: fcoe_pdu_offload_target_install
fcoe_pdu_offload_target_install:$(strip $(call get_prerequisites,fcoe_pdu_offload_target_install,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ${NORPMKERNELFLAG} == 1 ] ; then \
			$(MAKE) --no-print-directory -C $(NwSrc) chfcoe_install ; \
		else \
			( $(call installdrvrpm,chfcoe) ) && \
			( $(call logs,FCoE(PDU-Offload-Target),chfcoe,Install) ) || \
			( $(call logtemp,FCoE(PDU-Offload-Target),chfcoe,Install) )\
		fi ; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target  [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: scst_chfcoe_install
scst_chfcoe_install: scst_chfcoe_rpm
	@ $(call installdrvrpm,scst_chfcoe)

.PHONY: iscsi_pdu_target_install
iscsi_pdu_target_install:$(strip $(call get_prerequisites,iscsi_pdu_target_install,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
                if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                    $(MAKE) --no-print-directory -C $(NwSrc) iscsi_target ; \
                    $(MAKE) --no-print-directory -C $(NwSrc) iscsi_target_install ; \
		    $(call copyconfigfile) \
                else \
 	            ( $(call installdrvrpm,iscsi_pdu_target) ) && \
	            ( $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,Install) ) ||\
	            ( $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Install) ) \
                fi; \
	  else \
		echo -e "INFO : \t\tchiscsi_t4 [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: iscsi_pdu_initiator_install
iscsi_pdu_initiator_install:$(strip $(call get_prerequisites,iscsi_pdu_initiator_install,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ] " ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tInstall\tNot-supported" >> temp.log ;\
	  elif [ $(openssl) == "1" ] ; then \
	      if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) cxgbi ; \
	          $(MAKE) --no-print-directory -C $(NwSrc) cxgbi_install ; \
		  $(call copyconfigfile) \
	      else\
	       ( $(call installdrvrpm,iscsi_pdu_initiator) ) && \
	       ($(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Install)) || \
	       ($(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Install)) \
	       fi;\
	  else \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: rdma_block_device_install
rdma_block_device_install: $(strip $(call get_prerequisites,rdma_block_device_install,${is_rdma_block_device}))
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_rdma_block_device) -eq 1 ] ; then \
	        if [${NORPMKERNELFLAG} == 1 ] ; then \
	            $(MAKE) --no-print-directory -C $(NwSrc) rdma_block ; \
	            $(MAKE) --no-print-directory -C $(NwSrc) rdma_block_install ; \
	        else \
	           ( $(call installdrvrpm,rdma_block_device) ) && \
	           ($(call logs,RDMA-Block-Device,RDMA,Install)) || \
	           ($(call logtemp,RDMA-Block-Device,RDMA,Install)) \
	        fi ; \
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
		echo -e "RDMA-Block-Device\t\tRDMA\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: libs_debug_install
libs_debug_install:
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        $(call installwdudpdebug,install_dbg) \
	  else \
	        echo -e " "  ;\
	  fi; \

.PHONY: libs_install
libs_install:$(strip $(call get_prerequisites,libs_install,${is_iwarp}))
	@ echo " ";
ifeq ($(iwarp_libs),1)
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	           $(call checklibibverbs,libcxgb4_install,Install,iwarp-Libraries,libcxgb4) \
	           $(call checklibibverbs,install,Install,,WD_UDP) \
	        else\
	            ( ( $(call installdrvrpm,libs) ) && \
	            ( $(call logs,iWARP-lib,libcxgb4,Install) ) || \
	            ( $(call logtemp,iWARP-lib,libcxgb4,Install) )) ; \
	        fi;\
	  else \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "RDMA(iWARP-Lib)\t\tlibcxgb4\t\tInstall\tNot-supported" >> temp.log ;\
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\tInstall\tNot-supported" >> temp.log ;\
	  fi; \
	  $(call displaysummary,$(@),Install)
iwarp_libs = 2
endif

.PHONY: tools_install
tools_install:$(strip $(call get_prerequisites,tools_install,1))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;\
	  if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	       $(MAKE) --no-print-directory -C $(ToolSrc) install ;\
	       if [ ${BENCHMARK_FLAG} == 1 ] ; then \
	           $(MAKE) --no-print-directory -C $(ToolSrc) benchmarks_install ;\
	       fi ; \
	  else \
	       ( $(call installdrvrpm,tools) ) &&  \
	       ( $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Install) ) || \
	       ( $(call logtemp,Chelsio-utils(tools),$(cxgbtool_msg),Install) ) ;\
	  fi;\
	  if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
	     if [ ${UM_INST} -eq 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(ToolSrc) um_install ;\
	     fi; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: ba_tools_install
ba_tools_install:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools_install ;\
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: libibverbs_install
libibverbs_install: prep
	@ echo "################################################" ;\
          echo "#         Installing libibverbs Library        #" ;\
          echo "################################################" ;
	@ $(MAKE) --no-print-directory -C $(LibSrc) libibverbs_install ; 

.PHONY: librdmacm_install
librdmacm_install: prep
	@ echo "################################################" ;\
          echo "#         Installing librdmacm Library         #" ;\
          echo "################################################" ;
	@ $(MAKE) --no-print-directory -C $(LibSrc) librdmacm_install ;

.PHONY: autoconf_install
autoconf_install: prep 
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(AUTO_INST) -eq 1 ] ; then \
	     $(MAKE) --no-print-directory -C $(ToolSrc) autoconf ; \
	  fi ;

.PHONY: uninstall
uninstall: $(MAKECMDGOALS)
#uninstall: nic_uninstall vnic_uninstall toe_uninstall bonding_uninstall ipv6_uninstall iwarp_uninstall fcoe_full_offload_initiator_uninstall\
	iscsi_pdu_target_uninstall iscsi_pdu_initiator_uninstall libs_uninstall sniffer_uninstall tools_uninstall
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: nic_uninstall
nic_uninstall:
ifeq ($(nic),3)
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_nic) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,nic)) && ( $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ) \
	       || ($(call logtemp,Network(NIC),cxgb4,Uninstall) ) ) ;\
	  else \
	       echo -e "INFO : \t\tNIC [ Not supported ]" ; \
 	  fi;\
	  $(call displaysummary,$(@),Uninstall)
nic = 4
endif

.PHONY:nic_offload_uninstall
nic_offload_uninstall:
ifeq ($(nic),4)
	@ if [ ! -d "build" ] ; then \
	        $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_nic) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,nic_offload) ) && ( $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ) || \
	       ($(call logtemp,Network(NIC),cxgb4,Uninstall))) ;\
	       if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
                   if [ ${UM_UNINST} == 1 ] ; then \
	               $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
                   fi; \
	       fi ; \
	  else \
	       echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)
nic = 5
endif

.PHONY:nic_ipv4_uninstall
nic_ipv4_uninstall:
	@ if [ ! -d "build" ] ; then \
                $(MAKE) --no-print-directory prep;\
          fi ; \
          if [ $(is_nic) -eq 1 ] ; then \
               $(call uninstalldrvrpm,nic_offload) \
               $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ;\
               if [ ${DISTRO} == "SLES11sp2" ] || [ ${DISTRO} == "RHEL6.3" ] ||\
                   [ ${DISTRO} == "RHEL5.8" ]; then \
                   $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
               fi ; \
          else \
               echo -e "INFO : \t\tNIC [ Not supported ]" ; \
          fi;\
          $(call displaysummary,$(@),Uninstall)

.PHONY: bonding_uninstall
bonding_uninstall:
	@ if [ ! -d "build" ] ; then\
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bonding) -eq 1 ] ; then \
	        ( ( $(call uninstalldrvrpm,bonding) ) && ($(MAKE) --no-print-directory -C $(NwSrc) bonding_uninstall) \
	        || ($(call logtemp,Bonding-offload,bonding,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: vnic_uninstall
vnic_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_vnic) -eq 1 ]; then \
	       ( ( $(call uninstalldrvrpm,vnic)) && ($(MAKE) --no-print-directory -C $(NwSrc) vnic_uninstall) || \
               ($(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Uninstall))) ;\
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: toe_uninstall
toe_uninstall:
ifeq ($(toe),2)
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	       ( ( $(call uninstalldrvrpm,toe)) && ($(MAKE) --no-print-directory -C $(NwSrc) toe_uninstall) || \
	       ($(call logtemp,Network-offload(TOE),t4_tom,Uninstall))) ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)
toe = 3
endif

.PHONY: wdtoe_uninstall
wdtoe_uninstall:
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		   $(MAKE) --no-print-directory -C $(NwSrc) wdtoe_uninstall ;\
	           $(MAKE) --no-print-directory -C $(LibSrc) wdtoe_lib_uninstall ;\
	       else \
	           ( ( $(call uninstalldrvrpm,wdtoe) ) && ($(MAKE) --no-print-directory -C $(NwSrc) wdtoe_uninstall) || \
	           ($(call logtemp,WD-TOE,t4_tom,Uninstall))) ;\
               fi ; \
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: wdtoe_wdudp_uninstall
wdtoe_wdudp_uninstall: iwarp_uninstall wdtoe_uninstall
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: toe_ipv4_uninstall
toe_ipv4_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_toe) -eq 1 ]; then \
	      ( (  $(call uninstalldrvrpm,toe_ipv4)) && ($(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4_uninstall) || \
	      ($(call logtemp,Network-offload(TOE),t4_tom,Uninstall) )) ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: bypass_uninstall
bypass_uninstall:$(strip $(call get_prerequisites,bypass_uninstall,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 @ if [ ! -d "build" ] ; then\
	        $(MAKE) --no-print-directory prep;\
	   fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	        ( ($(call uninstalldrvrpm,bypass)) && ($(MAKE) --no-print-directory -C $(NwSrc) nic_bypass_uninstall) || \
	        ($(call logtemp,Network-Offload(Bypass),cxgb4,Uninstall))) ;\
	   else \
	       echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	   fi ; \
	   $(call displaysummary,$(@),Uninstall)

.PHONY: ipv6_uninstall
ipv6_uninstall: 
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ $(shell echo $$(uname -r) | grep 2\.6\.34 ) ]; then \
	           $(MAKE) --no-print-directory -C $(NwSrc) ipv6_uninstall ; \
	      else\
	           $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv6_uninstall ;\
	      fi;\
	      $(call uninstalldrvrpm,ipv6) \
	  else  \
		echo -e "INFO : \t\tipv6 " ; \
	  fi ;\
	  /bin/rm -f /lib/modules/$(shell uname -r)/updates/kernel/net/ipv6/ipv6.ko 2>/dev/null; \
	  $(call displaysummary,$(@),Uninstall)


.PHONY: iwarp_uninstall
iwarp_uninstall:$(strip $(call get_prerequisites,iwarp_uninstall,${is_iwarp}))
ifeq ($(iwarp),2)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	         $(call libcxgb4_cleanup) \
	         ( ( $(call uninstalldrvrpm,iwarp) ) &&  ( $(MAKE) --no-print-directory -C $(NwSrc) iwarp_uninstall; ) \
                   && ( $(call uninstallrdmatools) ) || ( $(call logtemp,RDMA(iWARP),iw_cxgb4,Uninstall) ) ) ; \
	  else \
	        echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)
iwarp = 3
endif

.PHONY: udp_offload_uninstall
udp_offload_uninstall:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	      ( ($(call uninstalldrvrpm,udp_offload)) && ($(MAKE) --no-print-directory -C $(NwSrc) udp_offload_uninstall ) || \
	      ($(call logtemp,UDP-Offload,t4_tom,Uninstall))); \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall) 

.PHONY: sniffer_uninstall
sniffer_uninstall: 
	@ if [ ! -d "build" ] ; then \
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_sniffer) -eq 1 ] ; then \
	       $(call uninstalldrvrpm,sniffer) \
	       $(MAKE) --no-print-directory -C $(ToolSrc) sniffer_uninstall ; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_full_offload_initiator_uninstall
fcoe_full_offload_initiator_uninstall:
	@ if [ ! -d "build" ] ; then \
		 $(MAKE) --no-print-directory prep;\
	  fi ;
	-@ find /etc/modprobe.d/ -name csiostor.conf -exec rm -f {} \+
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,fcoe_full_offload_initiator)) && ($(MAKE) --no-print-directory -C $(NwSrc) fcoe_uninstall) \
	       || ($(call logtemp,FCoE(full-offload-initiator),csiostor,Uninstall))); \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_full_offload_initiator_uninstall
iscsi_full_offload_initiator_uninstall:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_uninstall,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_pdu_offload_target_uninstall
fcoe_pdu_offload_target_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		( ($(call uninstalldrvrpm,chfcoe) ) && ($(MAKE) --no-print-directory -C $(NwSrc) chfcoe_uninstall) && \
	        ($(call uninstalldrvrpm,scst_chfcoe)) || ($(call logtemp,FCoE(pdu-offload-target),chfcoe,Uninstall))); \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_full_offload_target_uninstall
fcoe_full_offload_target_uninstall:
	@ if [ ! -d "build" ] ; then \
		 $(MAKE) --no-print-directory prep;\
	  fi ;
	@ if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  elif [ $(sles11) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  elif [ $(rhel6) ]  || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_pdu_initiator_uninstall
iscsi_pdu_initiator_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ] " ; \
	  else \
	       ( ($(call uninstalldrvrpm,iscsi_pdu_initiator)) && ($(MAKE) --no-print-directory -C $(NwSrc) oiscsi_uninstall) || \
	       ($(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Uninstall))) ;\
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_pdu_target_uninstall
iscsi_pdu_target_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,iscsi_pdu_target)) && ($(MAKE) --no-print-directory -C $(NwSrc) iscsi_target_uninstall) || \
	       ($(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\tchiscsi_t4 [ Not supported ]" ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: scst_chfcoe_uninstall
scst_chfcoe_uninstall:
	@ $(call uninstalldrvrpm,scst_chfcoe)

.PHONY: rdma_block_device_uninstall
rdma_block_device_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,rdma_block_device)) && ($(MAKE) --no-print-directory -C $(NwSrc) rdma_block_uninstall) || \
	       ($(call logtemp,RDMA-Block-Device,rbd,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: libs_uninstall
libs_uninstall:
	@ echo -e "" ;
ifeq ($(iwarp_libs),2)
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        ( ( $(call uninstalldrvrpm,libs) ) && ( $(call checklibibverbs,uninstall,Uninstall,,libcxgb4/WD_UDP) ) || ( $(call logtemp,iWARP-lib,libcxgb4,Uninstall) ) ) ; \
	  else \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall) 
iwarp_libs = 3
endif

.PHONY: tools_uninstall
tools_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  $(call uninstalldrvrpm,tools) \
	  $(MAKE) --no-print-directory -C $(ToolSrc) uninstall ;\
	  if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
	      if [ ${UM_UNINST} == 1 ]; then \
	         $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
	      fi;\
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: ba_tools_uninstall
ba_tools_uninstall:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools_uninstall ;\
	  else \
	      echo -e "INFO : \t\tBypass_tools [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: rpm
rpm:$(MAKECMDGOALS)

.PHONY: firmware_rpm
firmware_rpm:
ifeq ($(firmware),0)
	@ if [ ! -f chelsio-series4-firmware-$(vers)-*.${arch}.rpm ]  ; then \
	       $(MAKE) -C $(specs) firmware ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "FW rpm already present skipping the build"; \
	  else \
	       $(call logs,Firmware,t4fw-X.Y.Z.bin,rpm) \
	  fi;\
	  $(call displaysummary,$(@),rpm)
firmware = 1
endif

.PHONY: nic_rpm
nic_rpm:$(strip $(call get_prerequisites,nic_rpm,${is_nic}))
ifeq ($(nic),5)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4nic-$(vers)-*.${arch}.rpm ]  ; then \
	        $(MAKE) -C $(specs) nic ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC rpm already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,rpm) \
	     fi;\
	 else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
 	 fi;\
	 $(call displaysummary,$(@),rpm)
nic = 6
endif 

.PHONY: nic_offload_rpm
nic_offload_rpm: $(strip $(call get_prerequisites,nic_offload_rpm,${is_nic}))
ifeq ($(nic),6)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4-$(vers)-*.${arch}.rpm ]  ; then \
	        $(MAKE) -C $(specs) nic_offload ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC-OFFLOAD rpm already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,rpm) \
	     fi; \
	else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)
nic = 7
endif

.PHONY: nic_ipv4_rpm
nic_ipv4_rpm: $(strip $(call get_prerequisites,nic_ipv4_rpm,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
             if [ ! -f cxgb4-$(vers)-*.${arch}.rpm ]  ; then \
                $(MAKE) -C $(specs) nic_ipv4 ;\
             elif [ ${DEBUG} -eq 1 ] ; then\
                echo -e "Cxgb4 NIC-OFFLOAD-IPV4 rpm already present skipping the build"; \
             else \
                $(call logs,Network(NIC),cxgb4,rpm) \
             fi; \
        else \
             echo -e "INFO : \t\tNIC [ Not supported ]" ; \
             echo -e "Network(NIC_IPV4)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
         fi;\
         $(call displaysummary,$(@),rpm)

.PHONY: vnic_rpm
vnic_rpm: $(strip $(call get_prerequisites,vnic_rpm,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_vnic) -eq 1 ]; then \
	      if [ ! -f cxgb4vf-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) vnic ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4vf rpm already present skipping the build"; \
	     else \
	        $(call logs,SR-IOV_networking(vNIC),cxgb4vf,rpm)\
	     fi; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\trpm\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),rpm)

.PHONY: toe_rpm
toe_rpm: $(strip $(call get_prerequisites,toe_rpm,${is_toe}))
ifeq ($(toe),3)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	      if [ ! -f cxgb4toe-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) toe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE rpm already present skipping the build"; \
	      else \
	        $(call logs,Network-offload(TOE),t4_tom,rpm) \
	      fi; \
	      if [ $(ipv6_enable) -eq 0 ] ; then \
		echo -e "IPv6-offload\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	      fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-offload(TOE)\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	$(call displaysummary,$(@),rpm)
toe = 4
endif 

.PHONY: wdtoe_rpm
wdtoe_rpm: $(strip $(call get_prerequisites,wdtoe_rpm,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_wdtoe) -eq 1 ]; then \
	      if [ ! -f cxgb4wdtoe-${vers}-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) wdtoe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE rpm already present skipping the build"; \
	      else \
	          $(call logs,WD-TOE,t4_tom,rpm) \
	      fi; \
	 else \
	      echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	      echo -e "WD-TOE\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: wdtoe_wdudp_rpm
wdtoe_wdudp_rpm: wdtoe_rpm iwarp_rpm 
	@ $(call displaysummary,$(@),rpm)

.PHONY: toe_ipv4_rpm
toe_ipv4_rpm: $(strip $(call get_prerequisites,toe_ipv4_rpm,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	     if [ ! -f cxgb4toe-ipv4-$(vers)-*.${arch}.rpm ]  ; then \
	         $(MAKE) -C $(specs) toe_ipv4 ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	         echo -e "Cxgb4 TOE-ipv4 rpm already present skipping the build"; \
	     else \
	        $(call logs,Network-offload(TOE),t4_tom,rpm) \
	     fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-offload(TOE)\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: bypass_rpm
bypass_rpm: $(strip $(call get_prerequisites,bypass_rpm,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 @ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep;\
	   fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f bypass-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) --no-print-directory -C $(specs) bypass ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass rpm already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(Bypass),cxgb4,rpm) \
	     fi; \
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: ipv6_rpm
ipv6_rpm: $(strip $(call get_prerequisites,ipv6_rpm,${is_ipv6}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ $(shell echo $$(uname -r) | grep 2\.6\.34 ) ]; then \
	          if [ ! -f cxgb4ipv6-$(vers)-*.${arch}.rpm ]  ; then \
	              $(MAKE) -C $(specs) ipv6 ; \
		  elif [ ${DEBUG} -eq 1 ] ; then\
	              echo -e "IPv6 rpm already present skipping the build"; \
	          else \
		      $(call logs,IPv6-offload,ipv6,rpm) \
	          fi; \
	      else\
	          if [ ! -f cxgb4ipv6-$(vers)-*.${arch}.rpm ]  ; then \
	              $(MAKE) -C $(specs) toe_ipv6 ;\
		  elif [ ${DEBUG} -eq 1 ] ; then\
	              echo -e "Ipv6 rpm already present skipping the build"; \
	          else \
	              $(call logs,IPv6-offload,ipv6,rpm) \
	          fi; \
	      fi; \
	  else  \
		echo -e "INFO : \t\tipv6 " ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iwarp_rpm
iwarp_rpm: $(strip $(call get_prerequisites,iwarp_rpm,${is_iwarp}))
ifeq ($(iwarp),3)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	       if [ ! -f chiwarp-$(vers)-*.${arch}.rpm ]  ; then \
	  	   $(MAKE) -C $(specs) chiwarp ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iWARP rpm already present skipping the build"; \
	       else \
	           $(call logs,RDMA(iWARP),iw_cxgb4,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)
iwarp = 4
endif 

.PHONY: udp_offload_rpm
udp_offload_rpm:$(strip $(call get_prerequisites,udp_offload_rpm,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	       if [ ! -f cxgb4toe-$(vers)-*.${arch}.rpm ]  ; then \
		   $(MAKE) --no-print-directory -C $(specs) udp_offload ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "UDP-SO rpm already present skipping the build"; \
	       else \
	           $(call logs,UDP-Offload,t4_tom,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),rpm) 

.PHONY: sniffer_rpm
sniffer_rpm: $(strip $(call get_prerequisites,sniffer_rpm,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_sniffer) -eq 1 ] ; then \
	       if [ ! -f sniffer-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) sniffer ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "sniffer rpm already present skipping the build"; \
	       else \
	           $(call logs,Sniffer,wd_tcpdump,rpm)\
	       fi; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: bonding_rpm 
bonding_rpm: $(strip $(call get_prerequisites,bonding_rpm,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_bonding) -eq 1 ] ; then \
	      if [ ! -f bonding-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) bonding ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bonding rpm already present skipping the build"; \
	       else \
	           $(call logs,Bonding-offload,bonding,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-offload\t\tbonding\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: fcoe_full_offload_initiator_rpm
fcoe_full_offload_initiator_rpm: $(strip $(call get_prerequisites,fcoe_full_offload_initiator_rpm,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	      if [ ! -f csiostor-initiator-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) fcoe ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "FCoE initiator rpm already present skipping the build"; \
	       else \
	           $(call logs,FCoE(full-offload-initiator),csiostor,rpm) \
	       fi; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "INFO : \t\tiscsi_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_full_offload_initiator_rpm
iscsi_full_offload_initiator_rpm:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_rpm,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),rpm)

.PHONY: fcoe_pdu_offload_target_rpm
fcoe_pdu_offload_target_rpm: $(strip $(call get_prerequisites,fcoe_pdu_offload_target_rpm,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ! -f chfcoe-$(vers)-*.${arch}.rpm ]  ; then \
			$(MAKE) -C $(specs) chfcoe ;\
		elif [ ${DEBUG} -eq 1 ] ; then\
			echo -e "fcoe_pdu_offload_target rpm already present skipping the build"; \
		else \
			$(call logs,FCoE(PDU-Offload-Target),chfcoe,rpm) \
		fi; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
          $(call displaysummary,$(@),rpm)

.PHONY: fcoe_full_offload_target_rpm
fcoe_full_offload_target_rpm : fcoe_full_offload_target nic_offload_rpm
	@ if [ $(sles11) ] || [ $(rhel6) ] || [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ]  ||\
	         [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) -C $(specs) fcoe_target ;\
	  else \
		echo -e "FCoE(full-offload-target)\t\tcsiostor\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_pdu_target_rpm
iscsi_pdu_target_rpm: $(strip $(call get_prerequisites,iscsi_pdu_target_rpm,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	      if [ ! -f chiscsi-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) chiscsi ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iSCSI target rpm already present skipping the build"; \
	      else \
	           $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,rpm)\
	      fi; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_pdu_initiator_rpm
iscsi_pdu_initiator_rpm: $(strip $(call get_prerequisites,iscsi_pdu_initiator_rpm,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\trpm\tNot-supported" >> temp.log ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\trpm\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
	        if [ ! -f cxgb4i-$(vers)-*.${arch}.rpm ]  ; then \
		    $(MAKE) -C $(specs) cxgbi ;\
	        elif [ ${DEBUG} -eq 1 ] ; then\
	            echo -e "iSCSI initiator rpm already present skipping the build"; \
	       else \
	           $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm)\
	       fi; \
	  else \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: scst_chfcoe_rpm
scst_chfcoe_rpm:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@ echo "###########################################" ;\
	  echo "#         Building scst modules           #" ;\
	  echo "###########################################" ;
	@ ( cd $(NwSrc)/scst && $(MAKE) 2release KDIR=$(KOBJ) && $(MAKE) rpm KDIR=$(KOBJ) ) ;  \
	  ( if [ ! -d $(shell pwd)/rpmbuild/RPMS/$(arch)/ ] ; then \
	        mkdir -p $(shell pwd)/rpmbuild/RPMS/$(arch) ; \
	    fi ; \
	  cp -f $(NwSrc)/scst/rpmbuilddir/RPMS/$(arch)/*.rpm $(shell pwd)/rpmbuild/RPMS/$(arch)/ && \
	  cp -f $(NwSrc)/scst/scstadmin/rpmbuilddir/RPMS/$(arch)/*.rpm $(shell pwd)/rpmbuild/RPMS/$(arch)/ ) ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: rdma_block_device_rpm
rdma_block_device_rpm: $(strip $(call get_prerequisites,rdma_block_device_rpm,${is_rdma_block_device}))
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	      if [ ! -f rdma-block-device-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) rdma_block ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "RDMA Block Device rpm already present skipping the build"; \
	      else \
	           $(call logs,RDMA-Block-dev,rbd,rpm)\
	      fi; \
	  else \
		echo -e "INFO : \t\tRDMA-Block-Device [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: libs_rpm
libs_rpm: libs
ifeq ($(iwarp_libs),3)
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        $(MAKE) -C $(specs) libs ; \
	  else  \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "iWARP-lib\t\tlibcxgb4\t\trpm\tNot-supported" >> temp.log ; \
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\trpm\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),rpm)
iwarp_libs = 4
endif

.PHONY: wdtoe_libs_rpm
wdtoe_libs_rpm:
	@ if [ $(is_wdtoe) -eq 1 ] ; then \
	        $(MAKE) -C $(specs) wdtoe_libs ; \
	  else  \
	        echo -e "INFO : \t\tWDTOE-libraries [ Not supported ]" ; \
	        echo -e "WDTOE-lib\t\tlibwdtoe\t\trpm\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY:libibverbs_rpm 
libibverbs_rpm:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	        $(MAKE) -C $(LibSrc) libibverbs &> /dev/null;\
	        $(MAKE) -C $(specs) libibverbs &> /dev/null;\
	        libibverbs_ver="1.1.8";\
	        iwarp_libs_deps_rpm=(libibverbs libibverbs-devel libibverbs-utils);\
	         $(call install_rpm_always, $$iwarp_libs_deps_rpm, $$libibverbs_ver)\
	  fi; 

.PHONY:librdmacm_rpm
librdmacm_rpm:
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ $(is_iwarp) -eq 1 ] ; then \
		$(MAKE) -C $(LibSrc) librdmacm &> /dev/null;\
		$(MAKE) -C $(specs) librdmacm &> /dev/null;\
	        libcm_ver="1.0.21";\
	        iwarp_libs_deps_rpm=(librdmacm librdmacm-devel librdmacm-utils);\
	        $(call install_rpm_always, $$iwarp_libs_deps_rpm, $$libcm_ver)\
	  fi; 

.PHONY: libcxgb4_rpm
libcxgb4_rpm : libs
	@ if [ $(is_iwarp) -ne 1 ] ; then \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "iwarp-Libraries\t\trpm\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(specs) libcxgb4 ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: tools_rpm
tools_rpm : tools
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ ! -f chelsio-utils-$(vers)-*.${arch}.rpm ]  ; then \
	       $(MAKE) -C $(specs) chutils ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "Tools rpm already present skipping the build"; \
	  else \
	       $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),rpm) \
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY: ba_tools_rpm
ba_tools_rpm:  ba_tools
	@ if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f chelsio-bypass-utils-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) bypassutils ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass Tools rpm already present skipping the build"; \
	      else \
	          $(call logs,Bypass_tools,ba_*,rpm) \
	      fi; \
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: deb
deb:$(MAKECMDGOALS)

.PHONY: firmware_deb
firmware_deb: 
ifeq ($(firmware),1)
	@ if [ ! -f chelsio-series4-firmware-$(vers)-*.${arch}.deb ]  ; then \
	       $(MAKE) -C $(debrules) firmware ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "FW deb already present skipping the build"; \
	  else \
	       $(call logs,Firmware,t4fw-X.Y.Z.bin,deb) \
	  fi;\
	  $(call displaysummary,$(@),deb)
firmware = 2
endif

.PHONY: nic_deb
nic_deb:$(strip $(call get_prerequisites,nic_deb,${is_nic}))
ifeq ($(nic),7)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4nic-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) nic ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC deb already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,deb) \
	     fi;\
	 else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)
nic = 8
endif 

.PHONY: nic_offload_deb
nic_offload_deb: $(strip $(call get_prerequisites,nic_offload_deb,${is_nic}))
ifeq ($(nic),8)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) nic_offload ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC-OFFLOAD deb already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,deb) \
	     fi; \
	else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)
nic = 9
endif

.PHONY: vnic_deb
vnic_deb: $(strip $(call get_prerequisites,vnic_deb,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_vnic) -eq 1 ]; then \
	      if [ ! -f cxgb4vf-$(vers)-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) vnic ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4vf deb already present skipping the build"; \
	     else \
	        $(call logs,SR-IOV_networking(vNIC),cxgb4vf,deb)\
	     fi; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tdeb\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),deb)

.PHONY: toe_deb
toe_deb: $(strip $(call get_prerequisites,toe_deb,${is_toe}))
ifeq ($(toe),4)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	      if [ ! -f cxgb4toe-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) toe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE deb already present skipping the build"; \
	      else \
	        $(call logs,Network-offload(TOE),t4_tom,deb) \
	      fi; \
	      if [ $(ipv6_enable) -eq 0 ] ; then \
		echo -e "IPv6-offload\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	      fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-offload(TOE)\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	$(call displaysummary,$(@),deb)
toe = 5
endif 

.PHONY: wdtoe_deb
wdtoe_deb: $(strip $(call get_prerequisites,wdtoe_deb,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_wdtoe) -eq 1 ]; then \
	      if [ ! -f cxgb4wdtoe-${vers}-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) wdtoe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE deb already present skipping the build"; \
	      else \
	          $(call logs,WD-TOE,t4_tom,deb) \
	      fi; \
	 else \
	      echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	      echo -e "WD-TOE\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)

.PHONY: wdtoe_wdudp_deb
wdtoe_wdudp_deb: wdtoe_deb iwarp_deb 
	@ $(call displaysummary,$(@),deb)

.PHONY: bypass_deb
bypass_deb: $(strip $(call get_prerequisites,bypass_deb,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 @ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep;\
	   fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f bypass-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) --no-print-directory -C $(debrules) bypass ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass deb already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(Bypass),cxgb4,deb) \
	     fi; \
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iwarp_deb
iwarp_deb: $(strip $(call get_prerequisites,iwarp_deb,${is_iwarp}))
ifeq ($(iwarp),4)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	       if [ ! -f chiwarp-$(vers)-*.${arch}.deb ]  ; then \
		   $(MAKE) -C $(debrules) chiwarp ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iWARP deb already present skipping the build"; \
	       else \
	           $(call logs,RDMA(iWARP),iw_cxgb4,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)
iwarp = 5
endif 

.PHONY: udp_offload_deb
udp_offload_deb:$(strip $(call get_prerequisites,udp_offload_deb,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	       if [ ! -f cxgb4toe-$(vers)-*.${arch}.deb ]  ; then \
		   $(MAKE) --no-print-directory -C $(debrules) udp_offload ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "UDP-SO deb already present skipping the build"; \
	       else \
	           $(call logs,UDP-Offload,t4_tom,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),deb) 

.PHONY: sniffer_deb
sniffer_deb: $(strip $(call get_prerequisites,sniffer_deb,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_sniffer) -eq 1 ] ; then \
	       if [ ! -f sniffer-$(vers)-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) sniffer ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "sniffer deb already present skipping the build"; \
	       else \
	           $(call logs,Sniffer,wd_tcpdump,deb)\
	       fi; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: bonding_deb 
bonding_deb: $(strip $(call get_prerequisites,bonding_deb,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_bonding) -eq 1 ] ; then \
	      if [ ! -f bonding-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) bonding ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bonding deb already present skipping the build"; \
	       else \
	           $(call logs,Bonding-offload,bonding,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-offload\t\tbonding\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: fcoe_full_offload_initiator_deb
fcoe_full_offload_initiator_deb: $(strip $(call get_prerequisites,fcoe_full_offload_initiator_deb,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	      if [ ! -f csiostor-initiator-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) fcoe ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "FCoE initiator deb already present skipping the build"; \
	       else \
	           $(call logs,FCoE(full-offload-initiator),csiostor,deb) \
	       fi; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "INFO : \t\tiscsi_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tdeb\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iscsi_full_offload_initiator_deb
iscsi_full_offload_initiator_deb:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_deb,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),deb)

.PHONY: fcoe_pdu_offload_target_deb
fcoe_pdu_offload_target_deb: $(strip $(call get_prerequisites,fcoe_pdu_offload_target_deb,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ! -f chfcoe-$(vers)-*.${arch}.deb ]  ; then \
			$(MAKE) -C $(debrules) chfcoe ;\
		elif [ ${DEBUG} -eq 1 ] ; then\
			echo -e "fcoe_pdu_offload_target deb already present skipping the build"; \
		else \
			$(call logs,FCoE(PDU-Offload-Target),chfcoe,deb) \
		fi; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tdeb\tNot-supported" >> temp.log ;\
	  fi ; \
          $(call displaysummary,$(@),deb)

.PHONY: iscsi_pdu_target_deb
iscsi_pdu_target_deb: $(strip $(call get_prerequisites,iscsi_pdu_target_deb,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	      if [ ! -f chiscsi-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) chiscsi ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iSCSI target deb already present skipping the build"; \
	      else \
	           $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,deb)\
	      fi; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iscsi_pdu_initiator_deb
iscsi_pdu_initiator_deb: $(strip $(call get_prerequisites,iscsi_pdu_initiator_deb,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\tdeb\tNot-supported" >> temp.log ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tdeb\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
	        if [ ! -f cxgb4i-$(vers)-*.${arch}.deb ]  ; then \
		    $(MAKE) -C $(debrules) cxgbi ;\
	        elif [ ${DEBUG} -eq 1 ] ; then\
	            echo -e "iSCSI initiator deb already present skipping the build"; \
	       else \
	           $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,deb)\
	       fi; \
	  else \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: rdma_block_device_deb
rdma_block_device_deb: $(strip $(call get_prerequisites,rdma_block_device_deb,${is_rdma_block_device}))
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	      if [ ! -f rdma-block-device-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) rdma_block ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "RDMA Block Device deb already present skipping the build"; \
	      else \
	           $(call logs,RDMA-Block-dev,rbd,deb)\
	      fi; \
	  else \
		echo -e "INFO : \t\tRDMA-Block-Device [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: libs_deb
libs_deb: libs
ifeq ($(iwarp_libs),4)
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        $(MAKE) -C $(debrules) libs ; \
	  else  \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "iWARP-lib\t\tlibcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\tdeb\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),deb)
iwarp_libs = 4
endif

.PHONY: wdtoe_libs_deb
wdtoe_libs_deb:
	@ if [ $(is_wdtoe) -eq 1 ] ; then \
	        $(MAKE) -C $(debrules) wdtoe_libs ; \
	  else  \
	        echo -e "INFO : \t\tWDTOE-libraries [ Not supported ]" ; \
	        echo -e "WDTOE-lib\t\tlibwdtoe\t\tdeb\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),deb)

.PHONY: libcxgb4_deb
libcxgb4_deb : libs
	@ if [ $(is_iwarp) -ne 1 ] ; then \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "iwarp-Libraries\t\tdeb\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(debrules) libcxgb4_devel ;\
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: tools_deb
tools_deb : tools
	@ if [ ! -d "build" ] ; then \
		$(MAKE) --no-print-directory prep;\
	  fi ; 
	@ if [ ! -f chelsio-utils-$(vers)-*.${arch}.deb ]  ; then \
	       $(MAKE) -C $(debrules) chutils ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "Tools deb already present skipping the build"; \
	  else \
	       $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),deb) \
	  fi; \
	  $(call displaysummary,$(@),deb)

.PHONY: ba_tools_deb
ba_tools_deb:  ba_tools
	@ if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f chelsio-bypass-utils-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) bypassutils ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass Tools deb already present skipping the build"; \
	      else \
	          $(call logs,Bypass_tools,ba_*,deb) \
	      fi; \
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: clean
clean:
	@ echo "################################################## " ;\
	  echo "#          Cleaning Source/Build                 # " ;\
	  echo "################################################## " ;
	@ rm -rf build;

.PHONY: distclean
distclean:
	@ echo "################################################## " ;\
	  echo "#          Cleaning Source/Build/RPMDir          # " ;\
	  echo "################################################## " ;
	@ rm -rf build;
	@ rm -rf rpmbuild;
	@ rm -f scripts/deps.log;
	@ $(MAKE) --no-print-directory -C ${debrules} distclean

.PHONY: rpmclean
rpmclean: distclean
	@ echo "################################################## " ;\
          echo "#          Cleaning RPM Cluster Dir              # " ;\
          echo "################################################## " ;
	@ rm -rf RPM-Manager/DRIVER-RPMS/inbox/* ;
	@ rm -rf RPM-Manager/DRIVER-RPMS/ofed/* ;
	@ rm -rf RPM-Manager/OFED-RPMS/* ;
	@ rm -rf ChelsioUwire-2.12.0.3-RPM-Installer ;
	@ rm -rf ChelsioUwire-2.12.0.3-RPM-Installer.tar.gz ;

.PHONY: uninstall_all
uninstall_all:nic_uninstall toe_uninstall ipv6_uninstall iwarp_uninstall wdtoe_uninstall bonding_uninstall vnic_uninstall sniffer_uninstall fcoe_full_offload_initiator_uninstall fcoe_pdu_offload_target_uninstall iscsi_pdu_target_uninstall iscsi_pdu_initiator_uninstall libs_uninstall tools_uninstall bypass_uninstall rdma_block_device_uninstall
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: help
help: DEFAULT

.PHONY: prep
prep :
	$(call prepare)

.PHONY: removeallPrevious
removeallPrevious: distclean
	@ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	 if [ -f ${pwd}/uninstall.log ] ; then \
	     rm -f ${pwd}/uninstall.log ;\
	 fi;\
	echo "Uninstalling all previously installed drivers/libs. This step may take some time." ;\
	if [ -f ${pwd}/scripts/uninstall.py ]; then \
	    if [ ${DEBIAN} -eq 1 ] ; then \
	       python scripts/uninstall_deb.py inbox ; \
	    else \
	       python scripts/uninstall.py inbox ; \
	    fi ; \
	else \
	    echo -e "uninstall script missing";\
	    exit -1;\
	fi; \
	$(MAKE) uninstall_all UM_UNINST=${UM_UNINST} UNAME_R=${UNAME_R} >> ${pwd}/uninstall.log 2>&1

.PHONY: removeall
removeall:
	@ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ -f ${pwd}/uninstall.log ] ; then \
	       rm -f ${pwd}/uninstall.log ;\
	  fi;\
	  if [ -f ${pwd}/scripts/uninstall.py ]; then \
	      if [ ${DEBIAN} -eq 1 ] ; then \
	         python scripts/uninstall_deb.py inbox ; \
	      else \
	         python scripts/uninstall.py inbox ; \
	      fi ; \
	  else \
	       echo -e "uninstall script missing";\
	       exit -1;\
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY: removetools
removetools:
	@ if [ ${TOOLS_UNINST} -eq 1 ] ; then \
	      $(MAKE) --no-print-directory tools_uninstall > ${pwd}/uninstall.log 2>&1 ; \
	  fi ;

define getpatch
$(shell f=0; for kl in $(1)  ; do if [ $$(echo $(UNAME_R) | grep -c $$kl) -eq 1 ] ; then f=1 ; break ; fi ; done ;echo $$f ;)
endef

define printpatchKver
	if [ ${debug_patch} -eq 1 ] ; then \
		echo "Patching with $1 patch" ; \
	fi ;
endef

define prepare
	@ rm -rf temp.log deps.log 
	@ if [ ! -d "build" ] ; then \
		mkdir build ;\
	  else \
		rm -rf build ;\
		mkdir build;\
	  fi ;
	@ cp -rp src tools libs build;
	@ if [ $(patchSrc) -ne 0 ]; then \
	  if [ $(kerFlag) -eq 0 ] ; then \
		  if [ $(call getpatch,${r6x_kernels}) -eq 1 ]; then \
			$(call printpatchKver,RHEL6.X) \
			cd build ;\
			patch -p1 -f < src/patches/RHEL6.X* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${r7x_kernels}) -eq 1 ]; then \
			$(call printpatchKver,RHEL7.X) \
			cd build ;\
			patch -p1 -f < src/patches/RHEL7.X* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${s11sp1_kernel}) -eq 1 ]; then \
			$(call printpatchKver,SLES11sp1) \
			cd build ;\
			patch -p1 -f < src/patches/SLES11.1* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${s11x_kernels}) -eq 1 ]; then \
			$(call printpatchKver,SLES11.X) \
			cd build ;\
			patch -p1 -f < src/patches/SLES11X* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${s12_kernel}) -eq 1 ]; then \
			$(call printpatchKver,SLES12) \
			cd build ;\
			patch -p1 -f < src/patches/SLES12* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${u1404x_kernels}) -eq 1 ]; then \
			$(call printpatchKver,Ubuntu-14.04.X) \
			cd build ;\
			patch -p1 -f < src/patches/ubuntu-14.04.X* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${u14043_kernel}) -eq 1 ]; then \
			$(call printpatchKver,Ubuntu-14.04.3) \
			cd build ;\
			patch -p1 -f < src/patches/ubuntu-14.04.3* > $(NULL_OUT) ; \
		  fi ; \
	  else \
		  if [ $(call getpatch,${sw_kernels}) -eq 1 ]; then \
			$(call printpatchKver,None) \
			cd build ;\
			echo ; \
		  elif [ $(call getpatch,${v3x_kernels}) -eq 1 ]; then \
			$(call printpatchKver,3.X) \
			cd build ;\
			patch -p1 -f < src/patches/3.X* > $(NULL_OUT) ; \
		  elif [ $(call getpatch,${ex_kernels}) -eq 1 ]; then \
			$(call printpatchKver,3.4) \
			cd build ;\
			patch -p1 -f < src/patches/3.4* > $(NULL_OUT) ; \
		  fi;\
	  fi;\
	  if [ $$? -ne 0 ]; then \
	        echo "Failed to apply ${UNAME_R} patch." ; \
	  else \
	        echo ; \
	  fi; \
	  fi; 
	@ if [ $(shell uname -r | grep 2.6.32.36 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.36-0.5/bonding.h . ; \
		cp ../../../../bonding/2.6.32.36-0.5/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.36-0.5/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.54 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.54-0.3/bonding.h . ; \
		cp ../../../../bonding/2.6.32.54-0.3/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.54-0.3/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.46-0.3 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.46-0.3/bonding.h . ; \
		cp ../../../../bonding/2.6.32.46-0.3/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.46-0.3/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.59 ) ]; then \
                cd build/src/network/include/drivers/net/bonding/ ; \
                rm -f bond_3ad.h bond_alb.h bonding.h ; \
                cp ../../../../bonding/2.6.32.59-0.7/bonding.h . ; \
                cp ../../../../bonding/2.6.32.59-0.7/bond_3ad.h . ; \
                cp ../../../../bonding/2.6.32.59-0.7/bond_alb.h . ; \
                echo ; \
	  fi;
	@ if [ ${CHFCOE_TARGET} -eq 1 ]; then \
                ( cd build/src/network/cxgb4 && patch -p1 -f < ../../../src/chfcoe/linux/cxgb4_pofcoe.patch > /dev/null ) ; \
                echo ; \
          fi;                
	@ if [ -f $(OFA_DIR)/Module.symvers ] ; then \
		echo "copying Module.symvers" ;\
		cp -f $(OFA_DIR)/Module.symvers $(NwSrc)/network/. ;\
	  fi ;
endef

define checklibibverbs
	echo "################################################## " ;\
	echo "#          $(2)ing $4 Libraries         # " ;\
	echo "################################################## " ;\
	$(MAKE) --no-print-directory -C $(LibSrc) $(1) ; 
endef

define installwdudpdebug
        $(MAKE) --no-print-directory -C $(LibSrc) $(1); 
endef

define checksnifferlibibverbs
        if [ $(shell uname -p) == "x86_64" ] || [[ $(shell uname -p) =~ "ppc64" ]] && [ $(DEBIAN) -ne 1 ] ; then \
                if [ -f /usr/lib64/libibverbs.so ] || [ ${2} == "Uninstall"  ] ; then \
                        $(MAKE) --no-print-directory -C $(SnifferSrc) $(3); \
                else \
                        if [ $(3) ] ; then \
                                echo -e "$(1)\t\t$(4)\t\t$(2)\tNot-supported" >> temp.log ;\
                        fi ;\
                fi ; \
        else \
                if [ -f /usr/lib/libibverbs.so ] || [ ${2} == "Uninstall"  ] ; then \
                        $(MAKE) --no-print-directory -C $(SnifferSrc) $(3) ; \
                else \
                        if [ $(3) ] ; then \
                                echo -e "$(1)\t\t$(4)\t\t$(2)\tNot-supported" >> temp.log ;\
                        fi ;\
                fi ; \
        fi ;
endef
# install_rpm_always function installs the proivded RPM.
# It takes care of already installed RPM by either upgrading
# or downgrading.
define install_rpm_always
	iwarp_libs_deps_rpm="$(1)";\
	version="$(2)";\
	read  -rd '' version <<< "$$version";\
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
            echo -e "RPM LOC : $$rpm_location" ;\
	    echo -e "|$$version|";\
	    echo -e "RPM Install Sequence : $${iwarp_libs_deps_rpm[*]}" ; \
        fi;\
	for rpm in $${iwarp_libs_deps_rpm[*]}; do \
	    if [ ${DEBUG} -eq 1 ]; then\
	         echo -e "RPM : $$rpm" ;\
	    fi;\
            rpm -q $$rpm &> /dev/null; \
            if [ $$? -ne 0 ]; then  \
                if [ ${DEBUG} -eq 1 ] ; then \
                    echo "Installing RPM : $$rpm";\
                    echo -e "rpm -ivh $$rpm_location/$$rpm-$$version*"; \
                fi;\
                rpm -ivh $$rpm_location/$$rpm-$$version* &> /dev/null ;\
            else\
       	        if [ ${DEBUG} -eq 1 ] ; then \
                     echo "RPM : $$rpm already installed, trying to update.";\
       	             echo -e "rpm -Uvh $$rpm_location/$$rpm-$$version*"; \
                fi;\
       	        rpm -Uvh $$rpm_location/$$rpm-$$version* &> /dev/null;\
                if [ $$? -ne 0 ]; then  \
                    if [ ${DEBUG} -eq 1 ] ; then \
                        echo "Upgrade failed, probably newer version is installed, attempting a downgrade.";\
                        echo -e "rpm -Uvh --oldpackage $$rpm_location/$$rpm-$$version*"; \
                    fi;\
                    rpm -Uvh --oldpackage $$rpm_location/$$rpm-$$version* &> /dev/null ;\
                    if [ $$? -ne 0 ]; then  \
                        if [ ${DEBUG} -eq 1 ] ; then \
                            echo "Downgrade failed, attempting a force install.";\
                            echo -e "rpm -ivh --force $$rpm_location/$$rpm-$$version*"; \
                        fi;\
                        rpm -ivh --force $$rpm_location/$$rpm-$$version* &> /dev/null;\
       	            fi;\
       	        fi;\
            fi;\
       done;
endef

#installdrvrpm function installs driver RPM's and dependecies.
define installdrvrpm
	rpm_deps_chart="nic|chelsio-series4-firmware:cxgb4nic \
	               nic_offload|chelsio-series4-firmware:cxgb4 \
		       vnic|cxgb4vf \
		       toe|chelsio-series4-firmware:cxgb4:cxgb4toe \
		       wdtoe|chelsio-series4-firmware:cxgb4wdtoe:libwdtoe:libwdtoe_dbg \
		       udp_offload|chelsio-series4-firmware:cxgb4:cxgb4toe \
		       toe_ipv4|chelsio-series4-firmware:cxgb4:cxgb4toe-ipv4 \
		       bypass|chelsio-series4-firmware:bypass:chelsio-bypass-utils \
		       ipv6|chelsio-series4-firmware:cxgb4:cxgb4ipv6 \
		       iwarp|chelsio-series4-firmware:cxgb4:chiwarp:libcxgb4:libcxgb4-devel:${udp_libs} \
		       sniffer|sniffer \
		       bonding|chelsio-series4-firmware:cxgb4:cxgb4toe:bonding \
		       fcoe_full_offload_initiator|chelsio-series4-firmware:csiostor-initiator \
		       fcoe_full_offload_target|chelsio-series4-firmware:csiostor-target \
		       iscsi_pdu_target|chelsio-series4-firmware:cxgb4:cxgb4toe:chiscsi \
		       iscsi_pdu_initiator|chelsio-series4-firmware:cxgb4:cxgb4i \
		       scst_chfcoe|scst \
		       chfcoe|chelsio-series4-firmware:cxgb4:chfcoe \
		       rdma_block_device|rdma-block-device \
		       tools|chelsio-utils \
		       libs|libcxgb4:libcxgb4-devel:${udp_libs}" ;\
	if [ ${DEBIAN} -eq 1 ]; then \
	    deb_location=$(shell pwd)/debrules/debinaries;\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "DEB LOC : $$deb_location" ;\
	        echo -e "Installing RPM : $(1)";\
	    fi;\
	    for entry in $${rpm_deps_chart[*]}; do \
	         proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
	             echo -e "ENTRY : $$entry" ;\
	             echo -e "PROTO : $$proto";\
	         fi;\
	         if [ $$proto  == "$(1)" ]; then  \
	             deb_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	             if [ ${DEBUG} -eq 1 ] ; then \
	                  echo -e "got match for $(1) : $$entry" ;\
		     fi;\
		     break;\
	         fi; \
	    done ;\
	    deb_install_seq=$$(echo $$deb_install_seq | tr ":" " ");\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "DEB Install Sequence : $${deb_install_seq[*]}" ; \
	    fi;\
	    for deb in $${deb_install_seq[*]}; do \
	        dpkg -s $$deb &> /dev/null; \
	        if [ $$? -ne 0 ]; then  \
	            if [ ${DEBUG} -eq 1 ] ; then \
	                echo "Installing  : $$deb-$(vers)";\
		        echo -e "dpkg -i $$deb_location/$$deb-$(vers)*"; \
	            fi;\
	            dpkg -i $$deb_location/$$deb-$(vers)* ;\
	        elif [ ${DEBUG} -eq 1 ] ; then \
	            echo "DEB : $$deb already installed";\
	        fi;\
	        if [ $$deb == "cxgb4wdtoe" ] ; then \
	            dpkg -i $$deb_location/$$deb-$(vers)* 2>&1 > /dev/null ;\
	        fi;\
	    done;\
	else \
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM LOC : $$rpm_location" ;\
	    echo -e "Installing RPM : $(1)";\
	fi;\
	for entry in $${rpm_deps_chart[*]}; do \
	    proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "ENTRY : $$entry" ;\
	        echo -e "PROTO : $$proto";\
	    fi;\
	    if [ $$proto  == "$(1)" ]; then  \
	         rpm_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
		     echo -e "got match for $(1) : $$entry" ;\
		 fi;\
		 break;\
            fi; \
        done ;\
	rpm_install_seq=$$(echo $$rpm_install_seq | tr ":" " ");\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM Install Sequence : $${rpm_install_seq[*]}" ; \
	fi;\
	for rpm in $${rpm_install_seq[*]}; do \
	    rpm -q $$rpm &> /dev/null; \
            if [ $$? -ne 0 ]; then  \
	         if [ ${DEBUG} -eq 1 ] ; then \
		    echo "Installing RPM : $$rpm-$(vers)";\
	            echo -e "rpm -ivh $$rpm_location/$$rpm-$(vers)*"; \
	         fi;\
		 if [ $$rpm == "scst" ] ; then \
			for rpmbin in scst-${UNAME_R} scst-${UNAME_R}-devel scst-${UNAME_R}-debuginfo scstadmin scstadmin-debuginfo ; do \
				rpm -q $$rpmbin &> /dev/null; \
				if [ $$? -ne 0 ]; then  \
				 	rpm -ivh $$rpm_location/$$rpmbin* ;\
				fi ; \
			done; \
		 else \
	         	rpm -ivh $$rpm_location/$$rpm-$(vers)* ;\
		 fi ; \
	    elif [ ${DEBUG} -eq 1 ] ; then \
		 echo "RPM : $$rpm already installed";\
	    fi;\
	done; \
	fi ;
endef

#uninstalldrvrpm function uninstalls driver RPM's and dependecies.
define uninstalldrvrpm
	rpm_deps_chart="nic|cxgb4nic:cxgb4:chelsio-series4-firmware \
	               nic_offload|cxgb4:chelsio-series4-firmware \
		       vnic|cxgb4vf \
		       toe|cxgb4toe \
		       wdtoe|cxgb4wdtoe:cxgb4:chelsio-series4-firmware:libwdtoe:libwdtoe_dbg \
		       udp_offload|bonding:cxgb4toe:cxgb4:chelsio-series4-firmware \
		       toe_ipv4|cxgb4toe-ipv4 \
		       bypass|chelsio-bypass-utils:bypass:chelsio-series4-firmware \
		       ipv6|cxgb4ipv6 \
		       iwarp|libcxgb4_sock_debug:libcxgb4_udp_debug:libcxgb4_sock:libcxgb4_udp:libcxgb4-devel:libcxgb4:chiwarp \
		       sniffer|sniffer \
		       bonding|bonding \
		       fcoe_full_offload_initiator|csiostor-initiator \
		       fcoe_full_offload_target|csiostor-target \
		       chfcoe|chfcoe \
		       scst_chfcoe|scst \
		       iscsi_pdu_target|chiscsi \
		       iscsi_pdu_initiator|cxgb4i \
		       tools|chelsio-utils \
		       rdma_block_device|rdma-block-device \
		       libs|libcxgb4_sock_debug:libcxgb4_udp_debug:libcxgb4_sock:libcxgb4_udp:libcxgb4-devel:libcxgb4" ; \
	if [ ${DEBIAN} -eq 1 ] ; then \
	    deb_deps_chart="nic|cxgb4nic:cxgb4:chelsio-series4-firmware \
                       nic_offload|cxgb4:chelsio-series4-firmware \
                       vnic|cxgb4vf \
                       toe|cxgb4toe \
                       wdtoe|cxgb4wdtoe:cxgb4:chelsio-series4-firmware:libwdtoe:libwdtoe-dbg \
                       udp_offload|bonding:cxgb4toe:cxgb4:chelsio-series4-firmware \
                       toe_ipv4|cxgb4toe-ipv4 \
                       bypass|chelsio-bypass-utils:bypass:chelsio-series4-firmware \
                       ipv6|cxgb4ipv6 \
                       iwarp|libcxgb4-sock-dbg:libcxgb4-udp-dbg:libcxgb4-sock:libcxgb4-udp:libcxgb4-devel:libcxgb4:chiwarp \
                       sniffer|sniffer \
                       bonding|bonding \
                       fcoe_full_offload_initiator|csiostor-initiator \
                       fcoe_full_offload_target|csiostor-target \
                       chfcoe|chfcoe \
                       scst_chfcoe|scst \
                       iscsi_pdu_target|chiscsi \
                       iscsi_pdu_initiator|cxgb4i \
                       tools|chelsio-utils \
		       rdma_block_device|rdma-block-device \
                       libs|libcxgb4-sock-dbg:libcxgb4-udp-dbg:libcxgb4-sock:libcxgb4-udp:libcxgb4-devel:libcxgb4" ; \
	    deb_location=$(shell pwd)/debrules/debinaries;\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "Removing package : $(1)";\
	    fi;\
	    for entry in $${deb_deps_chart[*]}; do \
	       proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	       if [ ${DEBUG} -eq 1 ] ; then \
	          echo -e "ENTRY : $$entry" ;\
	          echo -e "PROTO : $$proto";\
	       fi;\
	       if [ $$proto  == "$(1)" ]; then  \
	          deb_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	          if [ ${DEBUG} -eq 1 ] ; then \
	             echo -e "got match for $(1) : $$entry" ;\
	          fi;\
	          break;\
	       fi; \
	    done ;\
	    deb_install_seq=$$(echo $$deb_install_seq | tr ":" " ");\
	    if [ ${DEBUG} -eq 1 ] ; then \
	       echo -e "DEB Uninstall Sequence : $${deb_install_seq[*]}" ; \
	    fi;\
	    for deb in $${deb_install_seq[*]}; do \
	       dpkg -s $$deb &> /dev/null; \
	       if [ $$? -eq 0 ]; then  \
	          if [ ${DEBUG} -eq 1 ] ; then \
	             echo "Uninstalling DEB : $$deb";\
	             echo -e "dpkg -r $$deb"; \
	             echo -e "dpkg -P $$deb"; \
	          fi;\
	          dpkg -r $$deb ; \
	          dpkg -P $$deb ; \
	       elif [ ${DEBUG} -eq 1 ] ; then \
	          echo "DEB : $$deb not uninstalled";\
	       fi;\
	    done; \
	else \
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "Removing package : $(1)";\
	fi;\
	for entry in $${rpm_deps_chart[*]}; do \
	    proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "ENTRY : $$entry" ;\
	        echo -e "PROTO : $$proto";\
	    fi;\
	    if [ $$proto  == "$(1)" ]; then  \
	         rpm_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
		     echo -e "got match for $(1) : $$entry" ;\
		 fi;\
		 break;\
            fi; \
        done ;\
	rpm_install_seq=$$(echo $$rpm_install_seq | tr ":" " ");\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM Uninstall Sequence : $${rpm_install_seq[*]}" ; \
	fi;\
	for rpm in $${rpm_install_seq[*]}; do \
	    if [ $$rpm == "scst" ] ; then \
                for rpmbin in scst-${UNAME_R} scst-${UNAME_R}-devel scst-${UNAME_R}-debuginfo scstadmin scstadmin-debuginfo ; do \
			rpm -q $$rpmbin &> /dev/null; \
                        if [ $$? -eq 0 ]; then  \
				if [ ${DEBUG} -eq 1 ] ; then \
		                    echo "Uninstalling RPM : $$rpmbin";\
				    echo -e "rpm -e $$rpmbin"; \
		                fi;\
				rpm -e $$rpmbin ;\
                        fi ; \
                done; \
		depmod -a ; \
	    fi;\
	    rpm -q $$rpm &> /dev/null; \
            if [ $$? -eq 0 ]; then  \
	         if [ ${DEBUG} -eq 1 ] ; then \
		    echo "Uninstalling RPM : $$rpm";\
	            echo -e "rpm -e $$rpm"; \
	         fi;\
	         rpm -e $$rpm ;\
	    elif [ ${DEBUG} -eq 1 ] ; then \
		 echo "RPM : $$rpm not uninstalled";\
	    fi;\
	done; \
	fi  ; 
endef

define installrdmatools
	if [ ! -f /usr/bin/rdma_lat ] && [ ! -f /sbin/rdma_lat ]; then \
		$(MAKE) --no-print-directory -C ${ToolSrc}/rdma_tools lat_install ;\
	fi ; \
	if [ ! -f /usr/bin/rdma_bw ] && [ ! -f /sbin/rdma_bw ]; then \
		$(MAKE) --no-print-directory -C ${ToolSrc}/rdma_tools bw_install ;\
	fi ;
endef

define uninstallrdmatools
	if [ -f /sbin/rdma_lat ]; then \
		rm -f /sbin/rdma_lat ; \
	fi ; \
	if [  -f /sbin/rdma_bw ]; then \
		rm -f /sbin/rdma_bw ;\
	fi ;
endef

define libcxgb4_cleanup
	find /usr/lib -name libcxgb4* -exec rm {} \+; \
	find /usr/lib64 -name libcxgb4* -exec rm {} \+; \
	find /usr/local/lib -name libcxgb4* -exec rm {} \+; \
	find /usr/local/lib64 -name libcxgb4* -exec rm {} \+; \
	ldconfig ;
endef

define copyconfigfile
if [ ${CONF} == "UNIFIED_WIRE" ] ; then \
    install -m 644 $(FwSrc)/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_TOE" ]; then \
    install -m 644 $(FwSrc)/high_capacity_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_RDMA" ] ; then \
    install -m 644 $(FwSrc)/high_capacity_rdma/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_rdma/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "LOW_LATENCY" ]; then \
    install -m 644 $(FwSrc)/low_latency_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/low_latency_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "UDP_OFFLOAD" ]; then \
    install -m 644 $(FwSrc)/udp_so_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/udp_so_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "T5_WIRE_DIRECT_LATENCY" ]; then \
    install -m 644 $(FwSrc)/edc_only_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/edc_only_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_WD" ]; then \
    install -m 644 $(FwSrc)/high_capacity_wd/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_wd/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "T5_HASH_FILTER" ]; then \
    install -m 644 $(FwSrc)/hash_filter_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/hash_filter_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "RDMA_PERFORMANCE" ]; then \
    install -m 644 $(FwSrc)/rdma_perf_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/rdma_perf_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "ISCSI_PERFORMANCE" ]; then \
    install -m 644 $(FwSrc)/iscsi_perf_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/iscsi_perf_config/t5-config.txt $(FwTar) ; \
elif [ ${CONF} == "MEMORY_FREE" ]; then \
    install -m 644 $(FwSrc)/memfree_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/memfree_config/t5-config.txt $(FwTar) ; \
fi ;
endef
    

define displaysummary
$(if $(filter $1,$(MAKECMDGOALS)),$(if $(filter 0,$(inst)),$(call display,$(2)),),)
endef

define display
$(eval j := $(shell expr $j + 1 ) ) \
if [ $(j) == $(k) ] ; then \
 $(call summary,$(1)) \
fi
endef

define summary
echo ; \
echo ; \
echo "***********************" ; \
echo "*      Summary        *" ; \
echo "***********************" ; \
echo "CONFIG = $(firm_config)" ; \
echo "Protocol   Modules\Libraries\Tools Action Status" | awk '{printf "%-30s%-30s%-15s%-10s\n", $$1,$$2,$$3,$$4}' ; \
echo "------------------------------------------------------------------------------------------" ;\
cat temp.log | grep $(1) | awk '{printf "%-30s%-30s%-15s%-10s\n", $$1,$$2,$$3,$$4}' ;\
if [ -f deps.log ] ; then \
echo -e "***********************" ; \
echo -e "*      Warnings       *" ; \
echo -e "***********************" ; \
cat deps.log ; \
mv -f deps.log scripts/. ;\
fi ;\
if [ $(inst) != 1 ] ; then \
 rm -rf temp.log; \
fi ; \
if [ $(installprecheck) == 1 ] ; then \
 ldconfig ; \
fi ;
endef

define logtemp
echo -e "$1\t\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log ;
endef
