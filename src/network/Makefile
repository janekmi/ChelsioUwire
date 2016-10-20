# Makefile for Chelsio T4 Offload driver.
# Copyright (c) 2009-2010 Chelsio Communications, Inc.
SHELL = /bin/bash

# Subdirectories to build, ordered list.
# This list order should not be modified do to symbol requirements.
ifeq ($(SUBDIRS),)
    SUBDIRS :=
else
    override SUBDIRS := $(SUBDIRS)
endif

# Define offload drivers.
offload_dirs := toecore t4_tom bonding iw_cxgb4

#Define nic and storage drivers.
nic_dirs := cxgb4
vnic_dirs := cxgb4vf
storage_dirs := csiostor

# Define offload options.
txzcopy = 1
offload_udp = 1
disable_ipv6_offload = 0
disable_mafo = 0


# Honor the -s (silent) make option.
verbose := $(if $(filter s,$(MAKEFLAGS)),,-v)

# Define paths.
srcdir := $(shell pwd)
topdir := $(shell cd $(srcdir)/.. && pwd)

# Define grep error output to NULL, since -s is not portable.
grep = grep 2>/dev/null

# Variables for RPM.
rpmdir = $(topdir)/rpmbuild
rpmrelease = custom

# Kernel directories.
KERNELRELEASE := $(shell uname -r)
# If KSRC=<path> is specified on the command line, KOBJ=<path> must
# also be specified. This is to avoid mixups if the kernel object path
# differs from the source path. A shortcut (KSRC=KOBJ) is to use KDIR.
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

# Only if KSRC/KOBJ were not defined on the command line.
KSRC ?= $(wildcard /lib/modules/$(KERNELRELEASE)/source)
KOBJ ?= $(wildcard /lib/modules/$(KERNELRELEASE)/build)

# If this is a 2.4 kernel and KSRC/KOBJ is still not defined, it is probably
# because there is no source|build directory in /lib/modules/version/. Try
# to use /usr/src/linux-2.4 and print a warning to the user that this may
# not be correct.
ifeq ($(KSRC),)
  ifneq ($(wildcard /usr/src/linux-2.4),)
    $(warning Using KSRC from /usr/src/linux-2.4.)
    $(warning This may or may not be the correct kernel.)
    $(warning If not, you can override this selection by)
    $(warning using KSRC=<path> or KDIR=<path>.)
    KSRC = /usr/src/linux-2.4
  endif
endif
ifeq ($(KOBJ),)
  ifneq ($(wildcard /usr/src/linux-2.4),)
    $(warning Using KOBJ from /usr/src/linux-2.4.)
    $(warning This may or may not be the correct kernel.)
    $(warning If not, you can override this selection by)
    $(warning using KOBJ=<path> or KDIR=<path>.)
    KOBJ = /usr/src/linux-2.4
  endif
endif
KINC  = $(KSRC)/include

# Define kernel files.
VERSION_H  := $(KOBJ)/include/linux/version.h
AUTOCONF_H := $(KOBJ)/include/generated/autoconf.h
UTSRELEASE_H  := $(KOBJ)/include/generated/utsrelease.h

ifneq ($(MAKECMDGOALS), clean)
  ifeq ($(wildcard $(VERSION_H)),)
    VERSION_H := $(KOBJ)/include/generated/uapi/linux/version.h
  endif
  ifeq ($(wildcard $(AUTOCONF_H)),)
    AUTOCONF_H := $(KOBJ)/include/linux/autoconf.h
  endif
  ifeq ($(wildcard $(UTSRELEASE_H)),)
    UTSRELEASE_H := $(KOBJ)/include/linux/utsrelease.h
  endif
  ifeq ($(wildcard $(UTSRELEASE_H)),)
    $(error NO utsrelease)
  endif
endif

# Define architecture and target(for RPM).
ARCH := $(shell uname -m)
target := $(ARCH)
override ARCH := $(shell echo $(ARCH) | sed 's/i.86/i386/')
ifeq ($(USER_ARCH),)
  ifeq ($(ARCH),ppc64)
    # Check if the kernel wants ppc64 or powerpc.
    ifeq ($(wildcard $(KOBJ)/arch/$(ARCH)),)
      override ARCH := powerpc
    endif
  endif
else
  # Honor the value of ARCH if specified by user.
  override ARCH := $(USER_ARCH)
endif

# This makefile performs configuration before building/installing any
# driver. The configuration is not required for targets that are not
# defined in 'config_targets'.
config_targets = nic vnic iwarp toe chbonding lld bypass \
                   rpm install uninstall storage $(SUBDIRS)
override config = 1

ifeq ($(MAKECMDGOALS),clean)
  override config = 0
endif

ifeq ($(filter-out install uninstall clean,  $(MAKECMDGOALS)),)
  override MAKECMDGOALS = toe vnic chbonding iwarp storage
else
  # Don't compile/install any storage drivers if using 'toe' target.
  ifeq ($(filter toe,$(MAKECMDGOALS)),toe)
    disable_storage = 1
  endif
endif

ifeq ($(filter $(config_targets),$(MAKECMDGOALS)),)
  override config = 0
endif


# Functions.
define path_check
$(if $(wildcard $(1)),$(1),)
endef
define reverse_sort
$(shell echo -e `echo "$(strip $(1))" |\
                 sed 's/[[:space:]]/\\\n/g'` | sort -r)
endef
define version_code
$(shell let x=`sed '/^\#define[[:space:]]*LINUX_VERSION_CODE/!d;\
                    s/.*LINUX_VERSION_CODE[[:space:]]*//' < $(1)\
               2>/dev/null`;\
        let a="$$x >> 16";\
        let x="$$x - ($$a << 16)";\
        let b="$$x >> 8";\
        let x="$$x - ($$b << 8)";\
        echo "$$a $$b $$x")
endef
define clean_symlinks
$(shell cd $(1)/;\
        if [ -z "$(2)" ]; then \
          pattern='*.[ch]';\
        else \
          pattern='$(2)';\
        fi;\
        for symlink in $$pattern; do \
	  [ ! -L $$symlink ] && continue;\
	  /bin/rm -f $$symlink;\
	done;)
endef
define get_pkgversion
$(shell pkgversion=`sed '/^Package Vers:[[:space:]]*/!d;\
                         s/^Package Vers:[[:space:]]*//' 2>/dev/null \
			 <$(topdir)/RELEASE`;\
        buildnumber=`sed '/^Build Number:[[:space:]]*/!d;\
                          s/^Build Number:[[:space:]]*//' 2>/dev/null \
			  <$(topdir)/RELEASE`;\
        if [ -n "$$pkgversion" ] && [ -n "$$buildnumber" ]; then \
	        echo "$$pkgversion.$$buildnumber";\
	else \
		echo "NONRELEASE";\
	fi;)
endef
define get_pkgname
$(shell pkgname=`sed '/^Package Name:[[:space:]]*/!d;\
                 s/^Package Name:[[:space:]]*\(.*\)-$(call get_pkgversion).*$$/\1/' \
	         2>/dev/null <$(topdir)/RELEASE`;\
	if [ -n "$$pkgname" ]; then \
		echo "$$pkgname";\
	else \
		echo "cxgb4toe";\
	fi;)
endef
define function_args
$(shell echo $1 | awk '{
i=index($$0,"(");
args=substr($$0,i+1);
n=split(args,b,");");
if(n>1){args=b[1]}else{exit};
n=split(args,b,"(");
for(i=1;i<=n;i++) {if(b[i]~/\)/){b[i]="()"}s=s b[i]};
out=split(s,a,",");
print out;
}'
)
endef

# Compile/install toe drivers.
ifeq ($(filter toe,$(MAKECMDGOALS)),toe)
  SUBDIRS := $(SUBDIRS) $(filter-out $(SUBDIRS), \
              toecore cxgb4 t4_tom)
endif

# Compile/install nic driver.
ifeq ($(filter nic,$(MAKECMDGOALS)),nic)
  SUBDIRS := $(SUBDIRS) $(filter-out $(SUBDIRS), cxgb4)
  disable_offload = 1
  disable_mafo = 1
endif

# Compile/install nic driver with offload flags target.
ifeq ($(filter lld,$(MAKECMDGOALS)),lld)
  SUBDIRS := $(SUBDIRS) $(filter-out $(SUBDIRS), cxgb4)
endif

# Compile/install vnic drivers.
ifeq ($(filter vnic,$(MAKECMDGOALS)),vnic)
  ifneq ($(filter toe,$(MAKECMDGOALS)),toe)
    disable_offload = 1
    disable_mafo = 1
  endif
  SUBDIRS := $(SUBDIRS)  $(filter-out $(SUBDIRS), cxgb4vf)
endif

# Compile/install bonding drivers.
ifeq ($(filter chbonding,$(MAKECMDGOALS)),chbonding)
  disable_bonding = 0
  SUBDIRS := $(SUBDIRS) $(filter-out $(SUBDIRS), toecore cxgb4 t4_tom bonding)
else
  disable_bonding = 1
endif

# Compile/install iwarp drivers.
ifeq ($(filter iwarp,$(MAKECMDGOALS)),iwarp)
  SUBDIRS := $(SUBDIRS) $(filter-out $(SUBDIRS), cxgb4 iw_cxgb4)
endif

# Allow the bypass code to build if using 'bypass' target.
ifeq ($(filter bypass,$(MAKECMDGOALS)),bypass)
  enable_bypass = 1
  disable_mafo = 1
  SUBDIRS := $(SUBDIRS)  $(filter-out $(SUBDIRS), toecore cxgb4 t4_tom)
endif

# Compile/install Storage drivers.
ifeq ($(filter storage,$(MAKECMDGOALS)),storage)
  SUBDIRS := $(SUBDIRS)  $(filter-out $(SUBDIRS), csiostor)
  disable_storage = 0
  enable_bypass = 0 
  ifneq ($(filter toe,$(MAKECMDGOALS)),toe)
    disable_mafo = 1
    disable_offload = 1
  endif
else
  disable_storage = 1
endif

# The following section of this makefile will be ignored if the target has
# been defined as not requiring configuration. eg: clean
ifeq ($(config),1)

# Defines and checks for RPM build.
pkgvers := $(call get_pkgversion)
pkgname := $(call get_pkgname)
ifneq ($(filter rpm,$(MAKECMDGOALS)),)
  ifeq ($(pkgvers),)
    override rpm_fail = 1
    $(warning Package version not found in $(topdir)/RELEASE)
  endif
  ifeq ($(pkgname),)
    override rpm_fail = 1
    $(warning Package name not found in $(topdir)/RELEASE)
  endif
  ifeq ($(rpm_fail),1)
    $(error ERROR: RPM build not possible)
  endif
endif

# Checks for kernel source and object directories.
ifeq ($(call path_check,$(KSRC)),)
  $(warning Be sure the kernel source is properly installed or \
            try specifying the kernel source tree using 'make KSRC=<path>')
  $(error ERROR: missing kernel source)
endif
ifeq ($(call path_check,$(KOBJ)),)
  $(warning Try specifying the kernel build tree using 'make KOBJ=<path>'.)
  $(error ERROR: missing kernel build)
endif

# Check kernel source and build directories are somewhat likely to be correct.
ifneq ($(notdir $(wildcard $(KSRC)/Makefile)),Makefile)
  $(warning There seems to be a problem with the kernel \
            source [$(KSRC)] directory.)
  $(error ERROR: missing kernel Makefile)
endif
ifneq ($(notdir $(wildcard $(KOBJ)/Makefile)),Makefile)
  $(warning There seems to be a problem with the kernel \
            build [$(KOBJ)] directory.)
  $(error ERROR: missing kernel Makefile)
endif

# Get kernel version code info.
KERNELVERSION := $(strip $(call version_code,$(VERSION_H)))
ifneq ($(words $(KERNELVERSION)), 3)
  $(error ERROR: unexpected kernel version \
          '$(shell echo $(KERNELVERSION) | sed 's/[[:space:]]/./g')')
endif

# Define kernel version details.
kversion       := $(word 1, $(KERNELVERSION))
kpatchlevel    := $(word 2, $(KERNELVERSION))
ksublevel      := $(word 3, $(KERNELVERSION))
# The kernel base version, excluding the EXTRAVERSION string.
kbaseversion   := $(kversion).$(kpatchlevel).$(ksublevel)
# The kernel series version.
kseries        := $(kversion).$(kpatchlevel)

ifeq ($(kseries),2.4)
  override modsym =
else
  override modsym = 1
endif

ifeq ($(modsym),1)
# Fix for variation of Module.symvers naming (thanks 2.6.17!).
# I need to know the file name of the module symver generated by the kernel
# during an external module build (MODPOST). Also used for kernels that don't
# automatically generate the module symver file during MODPOST (2.6.0-2.6.17?).
ifeq ($(shell $(grep) -c '^modulesymfile[[:space:]]*:\?=' \
                $(KSRC)/scripts/Makefile.modpost),1)
  modulesymfile := $(shell $(grep) '^modulesymfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
  kernelsymfile := $(shell $(grep) '^kernelsymfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
else
ifeq ($(shell $(grep) -c '^symverfile[[:space:]]*:\?=' \
                $(KSRC)/scripts/Makefile.modpost),1)
  symverfile    := $(shell $(grep) '^symverfile[[:space:]]*:\?=' \
                             $(KSRC)/scripts/Makefile.modpost)
  kernelsymfile := $(subst symverfile,kernelsymfile,$(symverfile))
endif
endif
modulesymfile ?= $(symverfile)
ifeq ($(modulesymfile),)
  $(warning The parsing of $(KSRC)/scripts/Makefile.modpost \
            is not making sense.)
  $(error ERROR cannot determine module symvers file)
endif

# Gnu make (3.80) bug #1516, $(eval ...) inside conditionals causes errors.
# This is fixed in v3.81 and some v3.80 (RHEL4/5) but not on SLES10.
# Workaround: include a separate makefile that does the eval.
ifeq ($(shell echo '$(modulesymfile)' | $(grep) -c '^[[:alnum:]_]\+[[:space:]]*:\?=[[:space:]]*.\+'),1)
  $(shell echo '$$(eval $$(modulesymfile))' > eval.mak)
  include eval.mak
  #$(eval $(modulesymfile))
else
  modulesymfile =
endif
ifeq ($(shell echo '$(kernelsymfile)' | $(grep) -c '^[[:alnum:]_]\+[[:space:]]*:\?=[[:space:]]*.\+'),1)
  $(shell echo '$$(eval $$(kernelsymfile))' > eval.mak)
  include eval.mak
  #$(eval $(kernelsymfile))
else
  kernelsymfile =
endif
modulesymfile := $(notdir $(modulesymfile))
kernelsymfile := $(notdir $(kernelsymfile))
$(shell [ -f eval.mak ] && /bin/rm -f eval.mak)

ifneq ($(words $(modulesymfile)),1)
  $(warning The parsing of $(KSRC)/scripts/Makefile.modpost \
            is not making sense.)
  $(warning You can try passing 'modulesymfile=Module.symvers' or \
            similar to make.)
  $(error ERROR cannot determine module symvers file)
endif
endif # modsym == 1

# Check for configured kernel.
ifeq ($(wildcard $(AUTOCONF_H)),)
  $(warning The kernel is not properly configured, try running \
            'make menuconfig' on your kernel.)
  $(error ERROR: kernel missing autoconf.h)
endif
# Check for built kernel.
ifeq ($(wildcard $(VERSION_H)),)
  $(warning The kernel has not been compiled. Try building your kernel \
            before building this driver.)
  $(error ERROR: kernel missing version.h)
endif

# Check that kernel supports modules.
ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_MODULES[[:space:]]\+1' $(AUTOCONF_H)),1)
  $(warning The kernel has not been configured for module support.)
  $(warning Try configuring the kernel to allow external modules and \
            recompile.)
  $(error ERROR: kernel CONFIG_MODULES not defined)
endif

# Get kernel UTS_RELEASE info.
ifneq ($(wildcard $(UTSRELEASE_H)),)
  ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+UTS_RELEASE' \
                  $(UTSRELEASE_H)),0)
    utsrelease := $(UTSRELEASE_H)
  endif
else
ifneq ($(wildcard $(KOBJ)/include/linux/version.h),)
  ifneq ($(shell $(grep) -c '^\#define[[:space:]]\+UTS_RELEASE' \
                  $(KOBJ)/include/linux/version.h),0)
    utsrelease := $(KOBJ)/include/linux/version.h
  endif
endif
endif
ifeq ($(utsrelease),)
  $(error ERROR: cannot locate kernel UTS_RELEASE)
endif
# Getting the UTS_RELEASE on RHEL3 had problems due to the multiple defines
# within the file. I can run this file through the C pre-processor and get 
# the actual UTS_RELEASE definition. This has only been tested on gcc, other
# compilers may not work.
utsrelease := $(strip $(shell $(CC) -E -dM -I $(KSRC)/include $(utsrelease) \
                        2>/dev/null| sed '/^\#define[[:space:]]*UTS_RELEASE/!d;\
		                          s/^\#define UTS_RELEASE[[:space:]]*"//;\
					  s/"//g'))

# The kernel local version string if defined in config.
klocalversion  := $(shell sed '/^CONFIG_LOCALVERSION=/!d;\
                               s/^CONFIG_LOCALVERSION="//;s/"//g'\
                            2>/dev/null < $(KOBJ)/.config)
# The complete kernel EXTRAVERSION string.
kextraversion  := $(subst $(kbaseversion),,$(utsrelease))
# The full kernel version should be the same as uts_release.
kernelversion  := $(utsrelease)

# The kernel EXTRAVERSION creates a unique problem, especially since
# kernel versioning extended into the EXTRAVERSION and distributions 
# add strings such as smp, largesmp, xen, etc or when additional minor
# version numbers are appended.
# Some code that we supply is dependent on the kernel version and
# parts of the EXTRAVERSION, but not dependent on some of the additional
# flags. This requires that I have a list of kernel version strings that
# could map to the source version we require. For example, if the
# kernel version is 2.6.9-67.ELsmp, we only care about the "2.6.9-67"
# part, therefore, I need to split the EXTRAVERSION accordingly.
# Another problem is when a user builds their own kernel, say 2.6.21.4
# and adds an additional string to EXTRAVERSION. The EXTRAVERSION is
# now ".4-custom" and I have to parse this with hopes of extracting
# only the ".4" part, resulting in the needed "2.6.21.4" version.
# Adding a BUGFIX version (int) field would be very helpfull!

# EXTRAVERSION as defined only in the Makefile.
extraversion1 := $(strip $(shell sed '/^EXTRAVERSION/!d;\
                                      s/^EXTRAVERSION[[:space:]]*=//;s/"//g'\
                                    < $(KSRC)/Makefile 2>/dev/null))
# SLES9 likes to put make code in their EXTRAVERSION define. Let the
# variables expand out to nothing, because the code will cause problems.
extraversion1 := $(shell echo $(extraversion1))
# EXTRAVERSION without local version.
extraversion2 := $(strip $(subst $(klocalversion),,$(kextraversion)))
# EXTRAVERSION with only the kernel .version (hopefully).
extraversion3 := $(strip $(shell echo $(kextraversion) |\
				  sed 's/\(^\.[0-9]*\).*/\1/'))
# EXTRAVERSION without the Redhat EL tag.
extraversion4 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\.EL.*//i'))
# EXTRAVERSION with the Redhat EL tag, but nothing else after.
extraversion5 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(\.EL\).*/\1/i'))
# EXTRAVERSION with the Redhat EL tag, including a number (el5).
extraversion6 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(\.EL[[:digit:]]*\).*/\1/i'))
# EXTRAVERSION without the Redhat hotfix/update kernel version number.
extraversion7 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\(\.EL\).*/\1\2/i'))
# EXTRAVERSION without the Redhat hotfix/update kernel version number with Redhat EL tag, including the number (el5).
extraversion8 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\(\.EL[[:digit:]]\).*/\1\2/i'))
# EXTRAVERSION with only the RHEL distro version
extraversion9 := $(strip $(shell echo $(kextraversion) |\
			          sed 's/\(.*\-[[:digit:]]*\)\..*\.EL[[:digit:]].*/\1/i'))

# All known EXTRAVERSION strings, duplicates removed.
extraversions  := $(strip $(sort $(kextraversion) \
			         $(extraversion1) \
			         $(extraversion2) \
			         $(extraversion3) \
			         $(extraversion4) \
			         $(extraversion5) \
			         $(extraversion6) \
			         $(extraversion7) \
			         $(extraversion8) \
			         $(extraversion9)))
# List of all possible kernel version names for target kernel.
all_kernels    := $(sort $(kbaseversion) \
		         $(foreach a,$(extraversions),$(kbaseversion)$(a)))
# A reverse ordered list. This is used primarily to search source code
# directory names to match the target kernel version.
kversions := $(call reverse_sort, $(all_kernels))

# Get Redhat release numbers if available.
RHEL_MAJOR = $(shell $(grep) RHEL_MAJOR $(VERSION_H) 2>/dev/null | \
			         sed 's/.*RHEL_MAJOR\s*//')
RHEL_MINOR = $(shell $(grep) RHEL_MINOR $(VERSION_H) 2>/dev/null | \
			         sed 's/.*RHEL_MINOR\s*//')

# Check if kernel has toecore built-in.
disable_toecore := $(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_TCP_OFFLOAD[[:space:]]\+1' \
                           $(AUTOCONF_H))


# Offload not supported if 2.6.5 and toecore not in kernel
ifeq ($(KERNELVERSION),2 6 5)
  ifneq ($(disable_toecore),1)
    disable_offload = 1
    disable_bonding = 1
    disable_mafo = 1
  endif
endif

# Some subdirectories don't need to be compiled, but need to be installed.
INSTALLDIRS := $(SUBDIRS) firmware
ifeq ($(wildcard protosram),protosram)
  INSTALLDIRS += protosram
endif

# Special cases for 2.4 series kernels.
ifeq ($(kseries),2.4)
  # Firmware auto-load not supported in 2.4.
  INSTALLDIRS := $(filter-out protosram firmware,$(INSTALLDIRS))
  # Kprobes not supported in 2.4.
  kprobes = 0
  # Modular offload driver not supported in 2.4.
  # Also disables offload bonding.
  disable_offload = 1
  disable_bonding = 1
  disable_mafo = 1
  ifneq ($(disable_storage),1)
    $(warning WARNING: The storage driver is not supported  \
              on the target kernel. The storage module will not be built.)
    disable_storage = 1
  endif
endif

ifneq ($(disable_storage),1)
  ifeq ($(kseries),2.6)
    ifeq ($(shell [[ $(ksublevel) -lt 30 ]] && echo 1),1)
      $(warning WARNING: The storage driver is not supported  \
                on the target kernel. The storage module will not be built.)
    disable_storage = 1
    endif
  endif
endif

# The iwarp driver needs GENERIC_ALLOCATOR enabled in kernel.
# Also, a flag so WDTOE knows what to do when it is disabled.
ifeq ($(shell $(grep) -c \
	'^\#define[[:space:]]\+CONFIG_GENERIC_ALLOCATOR[[:space:]]\+1' \
	$(AUTOCONF_H)),1)
  FLAGS += -DGEN_ALLOC
endif

# Ensure the kernel supports DCB and is configured.
ifeq ($(enable_dcb),1)
  ifneq ($(shell $(grep) -c \
         '^\#define[[:space:]]\+CONFIG_\(DCB\|DCB_MODULE\)[[:space:]]\+1' \
         $(AUTOCONF_H)),1)
    $(warning WARNING: DCB is not configured into or is unsupported \
              in this kernel. DCB support will be disabled.)
    post_msg += DCB support not compiled.\n
    override enable_dcb = 0
  endif
endif

# Disable TCPV6_OFFLOAD support if IPv6 not supported in kernel.
ifneq ($(disable_ipv6_offload),1)
  ifeq ($(shell $(grep) -c \
        '^\#define[[:space:]]\+CONFIG_\(IPV6\|IPV6_MODULE\)[[:space:]]\+1' \
        $(AUTOCONF_H)),0)
    $(warning WARNING: IPv6 is not configured or unsupported \
              in this kernel. IPv6 support will be disabled.)
    post_msg += IPV6 support disabled.\n
    override disable_ipv6_offload = 1
  endif
endif

# Don't compile/install offload drivers if defined 'disable_offload=1'.
ifeq ($(disable_offload),1)
  SUBDIRS     := $(filter-out $(offload_dirs),$(SUBDIRS))
  INSTALLDIRS := $(filter-out $(offload_dirs),$(INSTALLDIRS))
  disable_toecore = 1
  disable_bonding = 1
  disable_mafo = 1
  txzcopy = 0
  # Change pkgname when building only nic.
  pkgname := $(subst toe,,$(pkgname))
endif

ifeq ($(disable_bonding),1)
  SUBDIRS     := $(filter-out bonding,$(SUBDIRS))
  INSTALLDIRS := $(filter-out bonding,$(INSTALLDIRS))
endif

ifeq ($(disable_storage),1)
  SUBDIRS     := $(filter-out $(storage_dirs),$(SUBDIRS))
  INSTALLDIRS := $(filter-out $(storage_dirs),$(INSTALLDIRS))
endif

ifeq ($(disable_nic),1)
  SUBDIRS     := $(filter-out $(nic_dirs),$(SUBDIRS))
  INSTALLDIRS := $(filter-out $(nic_dirs),$(INSTALLDIRS))
endif
ifeq ($(disable_vnic),1)
  SUBDIRS     := $(filter-out $(vnic_dirs),$(SUBDIRS))
  INSTALLDIRS := $(filter-out $(vnic_dirs),$(INSTALLDIRS))
endif

# Don't compile/install toecore driver if defined 'disable_toecore=1'.
ifeq ($(disable_toecore),1)
  SUBDIRS     := $(filter-out toecore,$(SUBDIRS))
  INSTALLDIRS := $(filter-out toecore,$(INSTALLDIRS))
endif
ifeq ($(disable_iw_cxgb4),1)
  SUBDIRS     := $(filter-out iw_cxgb4,$(SUBDIRS))
  INSTALLDIRS := $(filter-out iw_cxgb4,$(INSTALLDIRS))
endif

# PR16634. Disable TXZCOPY for RHEL6.0 and RHEL6.1.
ifeq ($(RHEL_MAJOR), 6)
  ifeq ($(RHEL_MINOR), $(filter $(RHEL_MINOR), 0 1))
    override txzcopy = 0
  endif
endif

# Note: Define only FLAGS here. These will convert to CFLAGS in the sub-make.
# If the environment variable FLAGS is defined with make, things will break,
# use CFLAGS instead.
# General compiler flags.
# Kernel version 3.3+ moved include/asm to include/generated, which breaks
# outbox kernel drivers. Fix to include the new generated without code change.
ifeq ($(kversion),3)
  ifeq ($(shell [ $(kpatchlevel) -gt 2 ] && echo 1),1)
    override CARCH := $(ARCH)
    ifeq ($(CARCH),x86_64)
      override CARCH := x86
    endif
    FLAGS += -I$(KSRC)/arch/$(CARCH)/include/generated
  endif
endif

FLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
# For cxgb4 driver module.
FLAGS += -DCONFIG_CHELSIO_T4_CORE

#For crash debugging
ifneq ($(disable_cudbg),1)
  FLAGS += -DCUDBG_LITE
  FLAGS += -DCONFIG_CUDBG
endif

# For t4_tom and iw_cxgb4 driver modules.
ifneq ($(disable_offload),1)
  FLAGS += -DCONFIG_CHELSIO_T4_OFFLOAD_MODULE
  FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE
  FLAGS += -DCONFIG_CHELSIO_IO_SPIN
  FLAGS += -DCONFIG_INFINIBAND_CXGB4
  FLAGS += -DCONFIG_TCPV6_OFFLOAD
  FLAGS += -DSCSI_CXGB4_ISCSI
endif

# Disable IPV6 offload (remove ipv6 dependency in offload drivers).
ifeq ($(disable_ipv6_offload),1)
  FLAGS := $(filter-out -DCONFIG_TCPV6_OFFLOAD,$(FLAGS))
endif

# For toecore driver module.
ifeq ($(disable_toecore),1)
  FLAGS := $(filter-out -DCONFIG_TCP_OFFLOAD_MODULE,$(FLAGS))
  ifneq ($(disable_offload),1)
    FLAGS += -DCONFIG_TCP_OFFLOAD
  endif
  # Check for old offload.h
  ifeq ($(shell [ -e  $(KINC)/net/offload.h ] && echo 1), 1)
    ifeq ($(shell $(grep) -c 'sk_ofld_proto' $(KINC)/net/offload.h),0)
      FLAGS += -DOLD_OFFLOAD_H
    endif
  endif
  ifeq ($(shell [ -e $(KINC)/toedev.h ] && echo 1), 1)
    ifeq ($(shell $(grep) -c 'deactivate_offload' $(KINC)/linux/toedev.h),0)
      FLAGS += -DDEACTIVATE_OFFLOAD
    endif
  endif
endif

# Zero copy for offload modules.
ifeq ($(txzcopy),1)
  # Zero copy enabled architectures
    ifeq ($(filter $(ARCH),powerpc x86_64),$(ARCH))
      FLAGS += -DCONFIG_T4_ZCOPY_SENDMSG_MODULE
      # Zero copy huge table support architectures
      # Checked separately as this may diverge later from the outer conditional
      ifeq ($(ARCH),x86_64)
        FLAGS += -DCONFIG_T4_ZCOPY_HUGEPAGES
      endif
    endif
endif

# For offload bonding support.
ifneq ($(disable_bonding),1)
  FLAGS += -DBOND_SUPPORT
  PREPDIRS = bonding
endif

ifeq ($(offload_udp),1)
  FLAGS += -DUDP_OFFLOAD
  ifeq ($(filter $(FLAGS), -DCONFIG_TCPV6_OFFLOAD),-DCONFIG_TCPV6_OFFLOAD)
    FLAGS += -DCONFIG_UDPV6_OFFLOAD
  endif
endif

ifeq ($(enable_dcb),1)
  FLAGS += -DCONFIG_CXGB4_DCB
endif

ifeq ($(enable_wdtoe),1)
  FLAGS += -DWD_TOE
endif

#Enable MAFO only if both bonding and offload are available
ifeq ($(wildcard cxgb4/cxgb4_ma_failover.c),cxgb4/cxgb4_ma_failover.c)
  ifeq ($(wildcard t4_tom/t4tom_ma_failover.c),t4_tom/t4tom_ma_failover.c)
    ifneq ($(disable_offload), 1)
      ifneq ($(disable_bonding), 1)
        ifneq ($(disable_mafo), 1)
          FLAGS += -DCONFIG_T4_MA_FAILOVER
        endif
      else
        disable_mafo = 1
      endif
    else
      disable_mafo = 1
    endif
  endif
endif

# Other FLAGS.
ifneq ($(shell $(grep) -c 'IRQF_SHARED' $(KINC)/linux/interrupt.h),0)
  FLAGS += -DIRQF
endif
ifneq ($(shell $(grep) -c 'atomic_add_return' $(KINC)/asm/atomic.h),0)
  FLAGS += -DATOMIC_ADD_RETURN
endif
ifneq ($(shell $(grep) -c 'spin_trylock_irqsave' $(KINC)/linux/spinlock.h),0)
  FLAGS += -DSPIN_TRYLOCK_IRQSAVE
endif
ifneq ($(shell $(grep) -c 'rtnl_trylock' $(KINC)/linux/rtnetlink.h),0)
  FLAGS += -DRTNL_TRYLOCK
endif
ifneq ($(shell $(grep) -c 'gso_size' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_SIZE
endif
ifneq ($(shell $(grep) -c 'gso_type' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DGSO_TYPE
endif
ifneq ($(shell $(grep) -c 'kzalloc' $(KINC)/linux/slab.h),0)
  FLAGS += -DKZALLOC
endif
ifneq ($(shell $(grep) -c 'pci_error_handlers' $(KINC)/linux/pci.h),0)
  FLAGS += -DHAS_EEH
endif
ifneq ($(shell $(grep) -c 'vlan_group_get_device' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLANGRP
endif
ifneq ($(shell $(grep) -c 'skb_copy_from_linear_data' \
               $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_COPY
endif
ifneq ($(shell $(grep) -c 'i_private' $(KINC)/linux/fs.h),0)
  FLAGS += -DI_PRIVATE
endif
ifneq ($(shell $(grep) -c 'skb_network_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DNEW_SKB_OFFSET
endif
ifneq ($(shell $(grep) -c 'arp_hdr' $(KINC)/linux/if_arp.h),0)
  FLAGS += -DARP_HDR
endif
ifneq ($(shell $(grep) 'transport_header' $(KINC)/linux/skbuff.h | \
		$(grep) -c 'sk_buff_data_t'),0)
  FLAGS += -DTRANSPORT_HEADER
endif
# Linux 3.11 ditched the sk_buff_data_t data type which was either
# (unsigned int) or (char *) depending on the size of pointers and converted
# over to simply (__u16).
ifneq ($(shell $(grep) 'transport_header' $(KINC)/linux/skbuff.h | \
		$(grep) -c '__u16'),0)
  FLAGS += -DTRANSPORT_HEADER
endif
ifneq ($(wildcard $(KINC)/net/netdma.h),)
  FLAGS += -DNETDMA_IN_KERNEL
endif
ifneq ($(shell $(grep) -c 'ioat_sock' $(KINC)/net/netdma.h),0)
  FLAGS += -DIOAT_SOCK
endif
ifneq ($(shell sed '/ip_route_connect/,/{/!d' 2>/dev/null \
                 < $(KINC)/net/route.h | $(grep) -c 'flags'),0)
  FLAGS += -DIP_ROUTE_FLAGS
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_request' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_REQUEST
endif
ifneq ($(shell $(grep) -c 'security_inet_conn_established' \
               $(KINC)/linux/security.h),0)
  FLAGS += -DSEC_INET_CONN_ESTABLISHED
endif
ifneq ($(wildcard $(KINC)/net/netevent.h),)
  FLAGS += -DNETEVENT
endif
ifneq ($(shell $(grep) -c 'kallsyms_lookup_name' $(KOBJ)/$(modulesymfile)),0)
  FLAGS += -DKALLSYMS_LOOKUP_NAME
endif
ifneq ($(shell $(grep) -c 'symbol_name' $(KINC)/linux/kprobes.h),0)
  FLAGS += -DKPROBES_SYMBOL_NAME
endif
kallsyms := $(shell $(grep) '[[:space:]]\+kallsyms_lookup_name$$' /proc/kallsyms |\
                    cut -d' ' -f1)
ifneq ($(kallsyms),)
  FLAGS += -DKALLSYMS_LOOKUP=0x$(kallsyms)
endif

ifneq ($(shell $(grep) -c 'skb_transport_offset' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DT4_SKB_TRANSPORT_OFFSET
endif

ifneq ($(shell $(grep) -c 'ip_hdr' $(KINC)/linux/ip.h),0)
  FLAGS += -DT4_IP_HDR
endif

ifneq ($(shell $(grep) -c 'tcp_hdr' $(KINC)/linux/tcp.h),0)
  FLAGS += -DT4_TCP_HDR
endif

ifneq ($(shell $(grep) -c 'napi_struct' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DNAPI_UPDATE
endif

ifneq ($(shell $(grep) -c 'sk_filter_uncharge' $(KINC)/net/sock.h),0)
  FLAGS += -DSK_FILTER_UNCHARGE
endif

ifneq ($(shell $(grep) -c 'void inet_inherit_port' $(KINC)/net/inet_hashtables.h),0)
  FLAGS += -DINET_INHERIT_PORT
endif

ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/dma-mapping.h | \
		$(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif
# Linux 2.6.30 moved the prototype declaration of pci_dma_mapping_error()
# to asm-generic/pci-dma-compat.h ...
ifneq ($(shell $(grep) 'pci_dma_mapping_error' $(KINC)/asm-generic/pci-dma-compat.h | \
		$(grep) -c 'pci_dev'),0)
  FLAGS += -DPDEV_MAPPING
endif

ifneq ($(shell $(grep) -c 'vlan_dev_real_dev' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -DVLAN_DEV_API
endif

ifeq ($(shell [ -e  $(KINC)/linux/semaphore.h ] && echo 1), 1)
  FLAGS += -DLINUX_SEMAPHORE_H
endif

ifneq ($(shell $(grep) -c 'highest_sack' $(KINC)/linux/tcp.h),0)
  FLAGS += -DHIGHEST_SACK
endif

ifneq ($(shell $(grep) -c 'get_stats_count' $(KINC)/linux/ethtool.h),0)
  FLAGS += -DGET_STATS_COUNT
endif

ifeq ($(shell [ -e $(KINC)/net/inet_sock.h ] && echo 1),1)
  ifneq ($(shell $(grep) -c 'inet_daddr' $(KINC)/net/inet_sock.h),0)
    FLAGS += -DINET_PREFIX
  endif
endif

ifneq ($(shell $(grep) -c 'skb_dst_set' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_DST_SET
endif

ifneq ($(shell $(grep) -c 'netdev_get_tx_queue' $(KINC)/linux/netdevice.h),0)
  FLAGS += -DMQ_TX
endif

ifneq ($(shell $(grep) -c 'alloc_etherdev_mq' $(KINC)/linux/etherdevice.h),0)
  FLAGS += -DALLOC_ETHERDEV_MQ_DEF
endif

ifneq ($(shell $(grep) -c 'skb_record_rx_queue' $(KINC)/linux/skbuff.h),0)
  FLAGS += -DSKB_RECORD_RX_QUEUE
endif

ifneq ($(shell $(grep) -c 'ctl_name' $(KINC)/linux/sysctl.h),0)
  FLAGS += -DSYSCTL_CTL_NAME
endif

ifneq ($(shell $(grep) -c 'pci_try_reset_slot' $(KINC)/linux/pci.h),0)
  ifneq ($(shell $(grep) -c 'pci_try_reset_bus' $(KINC)/linux/pci.h),0)
    ifneq ($(shell $(grep) -c 'pci_probe_reset_slot' $(KINC)/linux/pci.h),0)
      ifneq ($(shell $(grep) -c 'pci_probe_reset_bus' $(KINC)/linux/pci.h),0)
        FLAGS += -DPCI_RESET_SLOTBUS
      endif
    endif
  endif
endif
ifneq ($(shell $(grep) -c 'const struct pci_error_handlers' $(KINC)/linux/pci.h),0)
  FLAGS += -DPCI_ERR_HANDLERS_CONST=const
else
  FLAGS += -DPCI_ERR_HANDLERS_CONST=
endif

ifneq ($(shell $(grep) -c 'kref_get_unless_zero' $(KINC)/linux/kref.h),0)
  FLAGS += -DKREF_GET_UNLESS_ZERO
endif

ifneq ($(OFA_DIR),)
  RDMA_INC = $(OFA_DIR)/include/rdma
  ifeq ($(wildcard $(RDMA_INC)/ib_verbs.h),)
    RDMA_INC = $(KINC)/rdma
  endif
else
  RDMA_INC = $(KINC)/rdma
endif

#
# see if iw_cm.h supports TOS
#
ifneq ($(wildcard $(RDMA_INC)/iw_cm.h),)
  ifneq ($(shell $(grep) -c 'tos' $(RDMA_INC)/iw_cm.h),0)
    FLAGS += -DIWARP_TOS_SUPPORT
  endif
endif

#
# see if iw_cm.h supports IPV6
#
ifneq ($(wildcard $(RDMA_INC)/iw_cm.h),)
  ifneq ($(shell $(grep) -c 'sockaddr_storage' $(RDMA_INC)/iw_cm.h),0)
    FLAGS += -DIWARP_IPV6_SUPPORT
  endif
endif

#
# see if kernel supports port mapping
#
ifneq ($(wildcard $(RDMA_INC)/iw_portmap.h),)
  FLAGS += -DIWARP_IWPM_SUPPORT
endif


ifneq ($(wildcard $(RDMA_INC)/ib_umem.h),)
  ifneq ($(shell $(grep) -c 'ib_umem_chunk' $(RDMA_INC)/ib_umem.h),0)
    FLAGS += -DHAVE_IB_UMEM_CHUNK
  endif
endif

ifneq ($(wildcard $(RDMA_INC)/ib_verbs.h),)
  # Grab the prototype definition of ib_register_device. Sometimes this is on
  # mulitple lines, so need to grab the entire definition from start to end(;)
  # and pull it together as a single string before counting the arguments.
  ibregdev = $(shell echo `sed -n '/ib_register_device/,/;/p'  \
                     $(RDMA_INC)/ib_verbs.h | sed 's/\s*//'` |\
                     $(grep) 'ib_register_device')
  ibregdev_args = $(call function_args,"$(ibregdev)")
  ifeq ($(ibregdev_args),2)
    FLAGS += -DIBREGDEV2
  endif
  ifneq ($(shell $(grep) -c 'struct ib_mw_bind_info' $(RDMA_INC)/ib_verbs.h),0)
    FLAGS += -DBIND_INFO
  endif
iballocmw = $(shell echo `sed -n '/ib_alloc_mw/,/;/p' \
		    $(RDMA_INC)/ib_verbs.h | sed 's/\*//'`)
iballocmw_args = $(call function_args,"$(iballocmw)")
  ifeq ($(iballocmw_args),2)
          FLAGS += -DIBALLOCMW2
  endif
endif

# For Kernel version 3.9+ don't include autoconf.h while building iWARP
iwarp_include = -include $(AUTOCONF_H) \
		$$(if $$(OFA_DIR), -I$(OFA_DIR)/include) \
		-Iinclude \
		$$(if $$(KBUILD_SRC), -Iinclude2 -I$$(srctree)/include) \
		-I$$(srctree)/arch/$$(SRCARCH)/include
# override iWARP include
ifeq ($(kversion),3)
  ifeq ($(shell [ $(kpatchlevel) -gt 9 ] && echo 1),1)
        override iwarp_include =
  endif
endif

# General compiler flags for 2.4 kernels.
ifeq ($(kseries),2.4)
  FLAGS += -DLINUX_2_4
  FLAGS += -DEXPORT_SYMTAB
  ifeq ($(ARCH),x86_64)
    FLAGS += -mcmodel=kernel
  endif
  ifneq ($(shell $(grep) -c 'if_mii' $(KINC)/linux/mii.h),0)
    FLAGS += -DIF_MII
  endif
endif

# Enable PO FCoE
ifeq ($(po_fcoe),1)
  ifneq ($(disable_offload),1)
    FLAGS += -DCONFIG_PO_FCOE
  else
    override po_fcoe = 0
  endif
endif

# Debug flags.
ifeq ($(DEBUG),1)
  FLAGS += -g
  ifeq ($(shell $(grep) -c '^\#define[[:space:]]\+CONFIG_DEBUG_FS[[:space:]]\+1' \
                $(AUTOCONF_H)),1)
    FLAGS += -DT4_TRACE
    ifneq ($(disable_offload),1)
      FLAGS += -DT4_TRACE_TOM
    endif
  endif
endif

PREPDIRS += $(SUBDIRS)
# Don't allow ARCH to overwrite the modified variable when passed to
# the sub-makes.
MAKEOVERRIDES := $(filter-out ARCH=%,$(MAKEOVERRIDES))
# Don't allow CFLAGS/EXTRA_CFLAGS to clobber definitions in sub-make.
MAKEOVERRIDES := $(filter-out CFLAGS=%,$(MAKEOVERRIDES))
MAKEOVERRIDES := $(filter-out EXTRA_CFLAGS=%,$(MAKEOVERRIDES))
# Exports.
export srcdir
export topdir
export KERNELRELEASE
export PREFIX
export INSTALL_MOD_DIR
export KSRC
export KOBJ
export ARCH
export FLAGS += $(CFLAGS) $(EXTRA_CFLAGS) $(CPPFLAGS)
export verbose
export utsrelease
export kversions
export kseries
export modulesymfile
export disable_bonding
export disable_offload
export disable_mafo
export bondsrc
export enable_dcb
export po_fcoe
export enable_wdtoe
export enable_bypass
export offload_udp
export iwarp_include 

endif # config

.PHONY: *.rpm
.PHONY: eval.mak

.PHONY: nic
nic: default

.PHONY: vnic
vnic: default

.PHONY: iwarp
iwarp: default

.PHONY: storage
storage: default

.PHONY: toe
toe: default

.PHONY: chbonding
chbonding: default

.PHONY: lld
lld: default

.PHONY: bypass
bypass: default

.PHONY: default
default: prep subdirs post

.PHONY: prep
prep: $(modulesymfile) subdirs-prep

$(modulesymfile):
	@-if (($(modsym))); then \
	    if [ -f $(OFA_DIR)/Module.symvers ] ; then \
		if [ -n "$(verbose)" ]; then \
			echo "#### Using OFA Module.symvers ####"; \
		fi; \
		cp -f $(OFA_DIR)/Module.symvers ./$(modulesymfile); \
	    else \
		cat $(KOBJ)/$(kernelsymfile) 2>/dev/null >./$(modulesymfile);\
	    fi; \
	  fi;

# We use the "prep" phase to allow the sub-directories to prepare for the
# global build.  This involves setting up symbolic links needed throughout
# the build, etc.
#
.PHONY: subdirs-prep
subdirs-prep:
	@echo Preparing for build ...
	@for subdir in $(PREPDIRS); do \
	    echo "#### Preparing $$subdir ####"; \
	    drvdir=$(shell pwd)/$$subdir $(MAKE) -C $$subdir prep || exit 1; \
	done


.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)

$(SUBDIRS):
	@if [ -n "$(verbose)" ]; then \
	   echo "#######################";\
	   printf "####  %-8s%5s####\n" $(@);\
	   echo "#######################";\
	 fi;
	@if (($(modsym))); then \
	   /bin/cp -f $(modulesymfile) $(@)/;\
	 fi;
	@drvdir=$(shell pwd)/$(@) $(MAKE) -C $(@);
	@if (($(modsym))); then \
	   /bin/cp -f $(@)/$(modulesymfile) .;\
	 fi;

.PHONY: install
install: default
	@-file=/etc/modprobe.d/libcxgb4.conf;\
	 lines=`grep -n "^install cxgb4 " $$file 2>/dev/null |\
	        sed 's/:.*//g' | sort -gr`;\
	 string="# Disabled by Chelsio Makefile on `date`";\
	 for i in $$lines; do \
	   sed -i "$$i"'s/^install cxgb4[[:space:]]/#install cxgb4 /' $$file;\
	   let i-=1;\
	   sed -i "$$i"'a'"$$string" $$file;\
	 done;
	@for dir in $(INSTALLDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir install ||\
		  exit 1;\
	 done;
	@-if (($(modsym))); then \
	   if [ -e $(modulesymfile) ]; then \
	     /bin/cp -f $(modulesymfile) $(KOBJ)/$(modulesymfile).Chelsio;\
	   fi;\
	 fi;
	-depmod

.PHONY: uninstall
uninstall:
	@-file=/etc/modprobe.d/libcxgb4.conf;\
	 string="# Disabled by Chelsio Makefile";\
	 lines=`grep -n "^$$string" $$file 2>/dev/null |\
	        sed 's/:.*//g' | sort -gr`;\
	 for i in $$lines; do \
	   sed -i "$$i"'d' $$file;\
	   sed -i "$$i"'s/^#//' $$file;\
	 done;
	@for dir in $(INSTALLDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir uninstall;\
	 done;
	-depmod

.PHONY: rpm
rpm: default
	 @package=$(pkgname)-$(pkgvers);\
	  /bin/mkdir -p $(rpmdir)/BUILD/$$package;\
	  /bin/mkdir -p $(rpmdir)/RPMS/$(target);\
	  rpmbuild -bb --define "_topdir $(rpmdir)" \
		       --define "srcdir $(srcdir)" \
		       --define "kversion $(kernelversion)" \
		       --define "version $(pkgvers)" \
		       --define "name $(pkgname)" \
		       --define "release $(rpmrelease)" \
		       --define "disable_offload $$(($(disable_offload)))" \
		       --define "disable_toecore $$(($(disable_toecore)))" \
		       --define "disable_bonding $$(($(disable_bonding)))" \
		       --target $(target) \
		      pkg.spec;\
	 /bin/cp -a \
	   $(rpmdir)/RPMS/$(target)/$$package-$(rpmrelease).$(target).rpm \
	   $(srcdir)/$$package-$(rpmrelease)-$(kernelversion).$(target).rpm;

.PHONY: clean
clean:
	@for dir in $(SUBDIRS); do \
	   drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir clean;\
	 done;
	-/bin/rm -f *.symvers eval.mak 2>/dev/null;

.PHONY: distclean
distclean: clean rpmclean
	-[ -n "$(rpmdir)" ] && /bin/rm -rf $(rpmdir) 2>/dev/null;
	-/bin/rm -f *.rpm 2>/dev/null;
	@-echo 'Removing t4_tom/module_support.c symlink'\
		$(call clean_symlinks,t4_tom,module_support.c)
	@-echo 'Removing iw_cxgb4/module_support.c symlink'\
		$(call clean_symlinks,iw_cxgb4,module_support.c)
	@-echo 'Removing krping/module_support.c symlink'\
		$(call clean_symlinks,krping,module_support.c)
	@-echo 'Removing toecore/module_support.c symlink'\
		$(call clean_symlinks,toecore,module_support.c)

.PHONY: rpmclean
rpmclean:
	@if [ -n "$(rpmdir)" ]; then \
	   /bin/rm -rf $(rpmdir);\
	 else \
	   exit 1;\
	 fi;

.PHONY: post
post:
	@if [ -n "$(post_msg)" ]; then \
	   echo -e "\nWARNING:\n $(post_msg)";\
	 fi;

.PHONY: help
help:
	@echo "Build Targets:";\
	 echo " nic               - Only build cxgb4 driver (no offload).";\
	 echo " vnic              - Only build cxgb4vf driver (no offload).";\
	 echo " toe               - Build toecore, cxgb4 and t4_tom drivers.";\
	 echo " lld               - Build cxgb4 driver with offload support.";\
	 echo " iwarp             - Build iwarp and cxgb4 drivers with offload support.";\
	 echo " chbonding         - Build toecore, cxgb4, t4_tom and bonding drivers.";\
	 echo " bypass            - Build driver with bypass adapter support.";\
	 echo " storage           - Only build the csiostor driver.";\
	 echo " rpm               - Generates a binary RPM. Can be used";\
	 echo "                     with other build targets and options.";\
	 echo "Other Targets:";\
	 echo " install           - Installs all compiled drivers.";\
	 echo " uninstall         - Uninstalls drivers.";\
	 echo " clean             - Removes all generated files.";\
	 echo " rpmclean          - Cleanup rpm directories.";\
	 echo " distclean         - Clean everything.";\
	 echo;\
	 echo "Build Options:";\
	 echo " bonding_version=<string> - Build the offload bonding driver against";\
	 echo "                     the kernel version listed.";\
	 echo " disable_offload=1 - Don't build any offload driver.";\
	 echo "                     Same as 'make nic'.";\
	 echo " disable_toecore=1 - Don't build the toecore driver.";\
	 echo "                     Useful if toecore is a kernel built-in.";\
	 echo " disable_ipv6_offload=1";\
	 echo "                   - Disable offloaded IPv6. Any IPv6 connection";\
	 echo "                     will be established through the host stack.";\
	 echo "                     This removes the ipv6 dependency within the";\
	 echo "                     toecore and tom drivers.";\
	 echo " disable_bonding   - Don't build the bonding driver.";\
	 echo " disable_storage   - Don't build the storage driver.";\
	 echo " disable_cudbg     - Disable cudbg crash debugging in driver.";\
	 echo " po_fcoe=1         - Enable POFCOE support for cxgb4 driver";\
	 echo " enable_dcb=1      - Enable DCBx support for cxgb4 driver";\
	 echo " enable_wdtoe=1    - Enable WDTOE support for TOE driver";\
	 echo " txzcopy=0         - Disable TX zero copy, on by default.";\
	 echo " KOBJ=<path>       - Kernel build (object) path.";\
	 echo " KSRC=<path>       - Kernel source path.";\
	 echo "                   - Note: When using KSRC or KOBJ, both must";\
	 echo "                           variables must be specified.";\
	 echo " KDIR=<path>       - Kernel build and source path. Shortcut for";\
	 echo "                     KOBJ=KSRC=<path>.";\
	 echo " DEBUG=1           - Enable debugging and tracing.";\
	 echo;\
	 echo "RPM Options:";\
	 echo " rpmrelease=<#>    - Change rpmrelease. Default is 0.";\
	 echo " pkgname=<string>  - Redefine package name.";\
	 echo " pkgvers=<string>  - Redefine package version.";\
	 echo;
