SHELL = /bin/bash
arch = $(shell uname -p)
release  = $(shell cat /etc/redhat-release)
rhel5 = $(shell if [ -f /etc/redhat-release ] ; then cat /etc/redhat-release | grep "Red Hat Enterprise Linux Server release 5." | awk -F "5" '{print $$1}' ; fi)
# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

pwd = $(shell pwd)
export pwd

.PHONY: bypass_tools
bypass_tools:
	@ echo "################################################## " ;\
          echo "#          Building bypass-utils                 # " ;\
          echo "################################################## " ;
	@ ( $(MAKE) -C $(pwd)/build/ && $(call logs,Bypass_tools,ba_*,Build) ) \
	  || $(call logtemp,Bypass_tools,ba_*,Build)

.PHONY: bypass_tools_install
bypass_tools_install: 
	@ echo "################################################## " ;\
	  echo "#        Installing bypass-utils                 # " ;\
	  echo "################################################## " ;
	@ $(call installTools) 

.PHONY: bypass_tools_uninstall
bypass_tools_uninstall: 
	@ echo "################################################## " ;\
	  echo "#        Uninstalling bypass-utils               # " ;\
	  echo "################################################## " ;
	@ $(call uninstallTools) 

define installTools
    install -v -m 755 build/t4/ba_server /sbin/;\
    install -v -m 755 build/t4/ba_client /sbin/;\
    install -m 744 build/ba-rc /etc/init.d/bad ;\
    ln -f /sbin/ba_client /sbin/redirect
    ln -f /sbin/ba_client /sbin/bypass
    $(call logs,Bypass_tools,ba_* ,Install) 
endef

define uninstallTools
    if [ -f /sbin/redirect ] ; then \
        unlink /sbin/redirect ; \
    fi ; \
    if [ -f /sbin/bypass ] ; then \
        unlink /sbin/bypass ; \
    fi ; \
    rm -f /etc/init.d/bad ;\
    rm -f /sbin/ba_server ;\
    rm -f /sbin/ba_client ;\
    $(call logs,Bypass_tools,ba_*,Uninstall) 
endef


define logtemp
echo -e "$1\t\t$2\t\t$3\tNot-Supported" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log ;
endef
