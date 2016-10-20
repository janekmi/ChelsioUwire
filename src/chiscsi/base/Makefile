SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# enable/disable target support
define unlink_target_src
$(shell cd $(1); \
	rm -f $(2)_en.c; \
	if [ -f $(2).c.orig ]; then \
	  mv $(2).c.orig $(2).c; \
	fi;)
endef

define link_target_src
$(shell cd $(1); \
	rm -f $(2)_en.c; \
	rm -f $(2)*.o; \
        if [ ! -f $(2).c.orig ]; then \
                mv $(2).c $(2).c.orig; \
        fi; \
        if [ $(3) -eq 1 ]; then \
                ln -fs $(2).c.orig $(2)_en.c; \
                rm -f lu_init.o; \
        fi;)
endef

ifeq ($(disable_vfs),1)
  v=$(call link_target_src,$(drvdir)/target,lu_vfs,0)
  $(warning vfs disabled.)
else
  FLAGS += -D__ISCSI_VFS__
  v=$(call link_target_src,$(drvdir)/target,lu_vfs,1)
  $(warning vfs enabled.)
endif

ifeq ($(enable_scst),1)
  ifeq ($(wildcard /usr/local/include/scst),)
    $(error ERROR: missing scst /usr/local/include/scst.)
  else
    scst_inc := /usr/local/include/scst
  endif
endif

ifeq ($(scst_inc),)
  enable_scst := 0   
  v=$(call link_target_src,$(drvdir)/target,lu_scst,0)
  $(warning scst disabled.)
else
  v=$(call link_target_src,$(drvdir)/target,lu_scst,1)
  $(warning scst enabled.)
  extra_symb += $(scst_inc)/Module.symvers

  FLAGS += -D__ISCSI_SCST__
  libscst=.scst
endif

ifeq ($(enable_lm),1)
  FLAGS += -D__ACL_LM__
  liblm=.lm
  v=$(call link_target_src,$(drvdir)/lunmask,lunmask,1)
  $(warning lm enabled.)
else
  v=$(call link_target_src,$(drvdir)/lunmask,lunmask,0)
  $(warning lm disabled.)
endif

ifeq ($(enable_bl),1)
  libbl=.bl
  $(warning bl enabled.)
else
  $(warning bL disabled.)
endif

ifeq ($(enable_notification),1)
  FLAGS += -D__ISCSI_NOTIFIER__
  $(warning event notification enabled.)
else
  $(warning event notification disabled.)
endif

ifeq ($(enable_dcb),1)
  ifneq ($(shell $(grep) -c 'dcb_app ' $(KINC)/net/dcbnl.h),0)
    FLAGS += -D__CH_DCB_SUPPORT__
    $(warning DCBx enabled.)
  else
    $(warning Unsupported kernel, DCBx not enabled.)
  endif
endif

ifneq ($(wildcard /etc/lsb-release),)
  ifneq ($(shell $(grep) "Ubuntu" /etc/lsb-release),)
    FLAGS += -DUBUNTU_VERSION_CODE
  endif
endif

ifneq ($(shell $(grep) -c 'vfs_unlink\(.*,.*,.*\)' $(KINC)/linux/fs.h),0)
  FLAGS += -DVFS_UNLINK_3PAR
endif

ifneq ($(shell $(grep) -c 'blkdev_get_by_path' $(KINC)/linux/fs.h),0)
  FLAGS += -DUSE_BLKDEV_FN
endif

ifneq ($(shell $(grep) -c 'vlan_dev_real_dev' $(KINC)/linux/if_vlan.h),0)
  FLAGS += -D_VLAN_DEV_API_
endif

ifneq ($(shell $(grep) -c ' cmd_type;' $(KINC)/linux/blkdev.h),0)
  FLAGS += -DBLK_RQ_HAS_CMD_TYPE
endif

ifeq ($(shell $(grep) -c ' resid_len;' $(KINC)/linux/blkdev.h),0)
  FLAGS += -DBLK_RQ_NO_RESID
endif

ifneq ($(shell $(grep) -c 'BLK_DEFAULT_SG_TIMEOUT' $(KINC)/linux/blkdev.h),0)
  FLAGS += -DBLK_RQ_HAS_TIMEOUT
endif

include $(srcdir)/common_flags.mk


ifeq ($(srcklib),1)
  include $(srcdir)/private/lib_defs.mk 
  LIB_CFLAGS += -D__KLIB__
  LIB_CFLAGS += $(COMMON_DEFS)
  LIB_CFLAGS += -I$(srcdir)/private/include
  LIB_CFLAGS += -I$(srcdir)/private/klib
  LIB_CFLAGS += -I$(drvdir)/klib/include
else
  # library name
  ifeq ($(ARCH),i386)
    ifeq ($(kregparm),1)
      libregpm := .regparm
    endif
  endif
  LIBOBJ := ../lib/klib/libchiscsi.$(ARCH)$(libregpm)$(libscst)$(liblm)$(libbl).a
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)
EXTRA_CFLAGS += -I$(srcdir)/includes
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += $(LIB_CFLAGS)
EXTRA_CFLAGS += -I.
EXTRA_CFLAGS += -I/usr/local/include/scst

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
					-o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

ifneq ($(SUBDIRS),)
  BASE_OBJS :=  $(patsubst $(SUBDIRS)/%.c,%.o,$(wildcard $(SUBDIRS)/*/*.c $(SUBDIRS)/*/*/*.c $(SUBDIRS)/*/*/*/*.c))
endif

obj-m := chiscsi_base.o
chiscsi_base-objs := $(BASE_OBJS) base.o $(LIBOBJ)

.PHONY: build
build:
	@$(MAKE) symverfile=$(symverfile) SCST_INC_DIR=$(scst_inc) KBUILD_EXTRA_SYMBOLS=$(extra_symb) -C $(KOBJ) SUBDIRS=$(shell pwd) modules

.PHONY: clean
clean:
	@-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd
	@-/bin/rm -rf */*.o */.*.o.* */.*.cmd
	@-/bin/rm -rf */*/*.o */*/.*.o.* */*/.*.cmd
	@-/bin/rm -rf */*/*/*.o */*/*/.*.o.* */*/.*.cmd
	@-/bin/rm -f klib
	@-echo "unlink target files ..."
	$(call unlink_target_src,$(drvdir)/target,lu_vfs)
	$(call unlink_target_src,$(drvdir)/target,lu_scst)
	$(call unlink_target_src,$(drvdir)/lunmask,lunmask)
