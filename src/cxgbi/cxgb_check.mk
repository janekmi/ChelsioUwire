ifneq ($(CXGB3TOE_SRC),)
  ifeq ($(wildcard $(CXGB3TOE_SRC)/cxgb3),)
    $(error ERROR! Invalid cxgb3 source $(CXGB3TOE_SRC).)
  endif
  ifeq ($(wildcard $(CXGB3TOE_SRC)/$(modulesymfile)),)
    $(error ERROR! Missing cxgb3 module symvers file \
                   $(CXGB3TOE_SRC)/$(modulesymfile))
  endif

  # for t3, only support 1.4.1 and up
  # cxgb3toe-1.4.1 onwards, use DRIVER_VERSION instead of DRV_VERSION
   ver := $(shell grep '^\#define DRIVER_VERSION' \
		$(CXGB3TOE_SRC)/cxgb3/version.h |\
		cut -f2 -d\")
$(warning cxgb3 version $(ver).)
  ifeq ($(ver),0-CVS)
    ver_major := 1
    ver_minor := 5
  else
    ver_words := $(subst ., ,$(ver))
    ver_major := $(word 1, $(ver_words))
    ver_minor := $(word 2, $(ver_words))
  endif
  ifeq ($(ver_major),)
    ver_major := 0
  endif
  ifeq ($(ver_minor),)
    ver_minor := 0
  endif

  ifeq ($(shell [ $(ver_major) -lt 1 ] && echo 1),1)
    $(warning cxgb3toe $(ver_major).$(ver_minor) < 1.x unsupported.)
    $(warning version string: $(ver), $(ver_words))
    $(error   ERROR: Unsupported cxgb3toe $(ver_major).$(ver_minor))
  endif

  ifeq ($(ver_major),1)
    ifeq ($(shell [ $(ver_minor) -lt 5 ] && echo 1),1)
      $(warning cxgb3toe $(ver_major).$(ver_minor) < 1.5 unsupported.)
      $(warning version string: $(ver), $(ver_words))
      $(error   ERROR: Unsupported cxgb3toe $(ver_major).$(ver_minor))
    endif
  endif

endif


ifneq ($(CXGB4TOE_SRC),)
  ifeq ($(wildcard $(CXGB4TOE_SRC)/cxgb4),)
    $(error ERROR! Invalid cxgb4 source $(CXGB4TOE_SRC).)
  endif
  ifeq ($(wildcard $(CXGB4TOE_SRC)/$(modulesymfile)),)
    $(error ERROR! Missing cxgb4 module symvers file \
                   $(CXGB4TOE_SRC)/$(modulesymfile))
  endif
endif
