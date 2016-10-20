SHELL = /bin/bash
# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif
PWD := $(shell pwd)
snifferSrc = $(PWD)/t4_sniffer
cudbgSrc = $(PWD)/cudbg/app/
mandir = /usr/share/man/man8
ARCH = $(shell uname -p)
stor =
ifeq ($(is_fcoe_full_offload_initiator),1)
  stor = storage=1
endif

export kdist

.PHONY: all
all:diags
	@ if [ ${BENCHMARK_FLAG} == 1 ] ; then \
	      ( $(MAKE) benchmarks ) ; \
	  fi ;
	@ echo "################################################## " ;\
	  echo "# Building Chelsio-utils(tools)                  # " ;\
	  echo "################################################## " ;
	@ echo "#######################";\
	  echo "####  $(cxgbtool_msg) ####";\
	  echo "#######################"; 
	@ ( $(MAKE) --no-print-directory -C $(cudbgSrc) && \
	    $(MAKE) --no-print-directory -C cxgbtool $(stor) && \
	       if [[ "$(ARCH)" =~ "ppc" ]] ; then \
	         ( $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Build) ) \
	       else \
	         ( $(MAKE) --no-print-directory -C cop  &&  ( $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Build)) ) ;\
	       fi ; ) \
                || $(call logtemp,Chelsio-utils(tools),$(cxgbtool_msg),Build)

.PHONY: diags
diags:
	@ echo "Preparing Diags..." ;
	@ if [[ $(ARCH) == "ppc64" ]] ; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_ppc64 \
                 $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ $(ARCH) == "ppc64le" ]] ; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_ppc64le \
                 $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ "$(kdist)" =~ "RHEL5" ]]; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_rhel5 \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ "$(kdist)" =~ "RHEL7" ]]; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_rhel7 \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ "$(kdist)" =~ "SLES11" ]]; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_sles11 \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ "$(kdist)" =~ "SLES12" ]]; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_sles12 \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  elif [[ "$(kdist)" =~ "ubuntu" ]]; then \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom_ubuntu \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  else \
	      cp -vf $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom_bins/t5seeprom \
	         $(PWD)/chelsio_adapter_config_v4/bin/t5seeprom ; \
	  fi ;

.PHONY: install
install:
	@ echo "################################################## " ;\
	  echo "# Installing Chelsio-utils(tools)                # " ;\
	  echo "################################################## " ;
	@ echo "#######################";\
	  echo "####  $(cxgbtool_msg) ####";\
	  echo "#######################"; 
	@ ( $(MAKE) --no-print-directory -C cxgbtool $(stor) install && \
              if [[ "$(ARCH)" =~ "ppc" ]] ; then \
	         ( $(call logs,Chelsio-utils(tools),cxgbtool,Install) ) \
	       else \
	         ( $(MAKE) --no-print-directory -C cop  &&  ( $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Install)) && \
	          ( install -m 744 wdload /sbin ) && ( install -m 744 wdunload /sbin )) ;\
	       fi ; ) \
                || $(call logtemp,Chelsio-utils(tools),$(cxgbtool_msg),Install)
	@ install -D -v -m 755 $(cudbgSrc)/cudbg_app /sbin/ ;
	@ install -m 744 t4_perftune.sh /sbin ;
	@ install -m 744 chstatus /sbin ;
	@ install -m 744 chsetup /sbin ;
	@ install -m 755 chdebug /sbin ;
	@ install -m 744 uname_r /sbin ;
	@ install -m 744 chiscsi_set_affinity.sh /sbin ;
	@ install -m 744 t4_latencytune.sh /sbin ;
	@ ( cd chelsio_adapter_config_v4 ; ./install.sh ) ;

.PHONY:benchmarks
benchmarks:
	@ echo "################################################## " ;\
          echo "# Building Benchmarks Tools                      # " ;\
          echo "################################################## " ;
	-@ ( cd benchmarks/netperf/ ; make distclean > /dev/null 2>&1 )
	-@ ( cd benchmarks/netperf/ ; ./autogen.sh; ./configure; make )
	-@ ( cd benchmarks/iperf/; ./autogen.sh; ./configure ; make )
	-@ ( cd benchmarks/netpipe/ ; make)
	@ if [[ "${ARCH}" =~ "ppc" ]] ; then \
	    echo ; \
	  else \
	    ( cd benchmarks/hpcbench/udp/ ; make ) ;\
	    ( cd benchmarks/sockperf/; ./autogen.sh; ./configure --prefix=/usr; make ) ; \
	    ( cd benchmarks/sockperf-lite/; ./configure --prefix=/usr --program-suffix=-lite ; make && cp src/sockperf src/sockperf-lite ) ; \
	  fi ; 
	-@ ( cd benchmarks/hpcbench/tcp/ ; make )

.PHONY:benchmarks_install
benchmarks_install: 
	@ echo "################################################## " ;\
          echo "# Installing Benchmarks Tools                    # " ;\
          echo "################################################## " ;
	-@ ( cd benchmarks/netperf/ ; make install)
	@ if [[ "${ARCH}" =~ "ppc" ]] ; then \
	    echo ; \
	  else \
	    ( cd benchmarks/sockperf/; make install) ; \
	    ( cd benchmarks/sockperf-lite/; make install) ; \
	    ( cd benchmarks/hpcbench/udp/ ; make ; install -m 744 udpserver /sbin ; install -m 744 udptest /sbin ) ; \
	  fi ;
	-@ ( cd benchmarks/iperf/; make install)
	-@ ( cd benchmarks/netpipe/ ; install -m 744 NPtcp /sbin)
	-@ ( cd benchmarks/hpcbench/tcp/ ; make ; install -m 744 tcpserver /sbin ; install -m 744 tcptest /sbin)

.PHONY: sniffer
sniffer:
	@ ( $(MAKE) --no-print-directory -C $(snifferSrc) && \
	  $(call logs,Sniffer,wd_tcpdump,Build) ) || \
	  $(call logtemp,Sniffer,wd_tcpdump,Build) 
	  

.PHONY: sniffer_install
sniffer_install:
	@ ( install -D -v -m 755 $(snifferSrc)/tcpdump-4.1.1/wd_tcpdump_trace /sbin && \
	  install -D -v -m 755 $(snifferSrc)/tcpdump-4.1.1/wd_tcpdump /sbin && \
	  install -D -v -m 755 $(snifferSrc)/sniffer_rdma_filter/sniffer /sbin/wd_sniffer && \
	  $(call logs,Sniffer,wd_tcpdump,Install) ) || \
	  $(call logtemp,Sniffer,wd_tcpdump,Install) 

.PHONY: sniffer_uninstall
sniffer_uninstall:
	@ ( rm -rvf /sbin/wd_tcpdump_trace /sbin/wd_tcpdump /sbin/wd_sniffer && \
	  $(call logs,Sniffer,wd_tcpdump,Uninstall) ) || \
	  $(call logtemp,Sniffer,wd_tcpdump,Uninstall) 

.PHONY: autoconf
autoconf:
	@ ( cd autoconf-2.63 ; ./configure --bindir=/usr/bin 2>/dev/null ; $(MAKE) install 2>/dev/null ;)

.PHONY: um_install
um_install:
	@ echo "################################################## " ;\
          echo "# Installing Chelsio Unified Manager             # " ;\
          echo "################################################## " ;
	@ if [ ${DISTRO} == "SLES11sp3" ]; then\
		( $(call installum,SLES11sp3,$(UM_VERSION) ) && $(call logs,Chelsio-Mgmt,UM,Install) )\
                || $(call logtemp,Chelsio-Mgmt,UM,Install)\
	  elif [ ${DISTRO} == "RHEL6.6"   ]; then\
		( $(call installum,RHEL6.6,$(UM_VERSION) ) && $(call logs,Chelsio-Mgmt,UM,Install) )\
                || $(call logtemp,Chelsio-Mgmt,UM,Install)\
	  fi;

.PHONY: um_uninstall
um_uninstall:
	@ echo "################################################## " ;\
          echo "# Uninstalling Chelsio Unified Manager           # " ;\
          echo "################################################## " ;
	@ if [ ${DISTRO} == "SLES11sp3" ]; then\
		( $(call uninstallum,SLES11sp3 ) && $(call logs,Chelsio-Mgmt,UM,Uninstall) )\
                || $(call logtemp,Chelsio-Mgmt,UM,Uninstall)\
	  elif [ ${DISTRO} == "RHEL6.6" ]; then\
		( $(call uninstallum,RHEL6.6 ) && $(call logs,Chelsio-Mgmt,UM,Uninstall) )\
                || $(call logtemp,Chelsio-Mgmt,UM,Uninstall)\
	  fi; 

.PHONY: uninstall
uninstall:
	@ echo "################################################## " ;\
	  echo "# Uninstalling Chelsio-utils(tools)              # " ;\
	  echo "################################################## " ;
	@ echo "#######################";\
	  echo "####  $(cxgbtool_msg) ####";\
	  echo "#######################";
	@ ( rm -rf /etc/modprobe.d/chelsio.conf ; rm -rf /sbin/cxgbtool ; rm -rf /sbin/cop ;\
	    rm -rf $(mandir)/cxgbtool.8.gz $(mandir)/cop.8.gz ; rm -rf /sbin/t4_perftune.sh ; rm -rf /sbin/t4_latencytune.sh ;\
	    rm -fr /sbin/wdload ; rm -rf /sbin/wdunload ; rm -rf /sbin/uname_r ; rm -fr /sbin/chsetup ; rm -fr /sbin/chstatus ;\
	    rm -rf /sbin/tcpserver ; rm -rf /sbin/tcptest ; rm -rf /sbin/udpserver ; rm -rf /sbin/udptest ; rm -rf /usr/bin/sockperf ; \
	    rm -rf /usr/local/bin/netperf ; rm -rf /usr/local/bin/netserver ;\
	    rm -rf /usr/local/bin/iperf ; rm -rf /sbin/netpipe ; rm -rf /sbin/bootcfg ; rm -rf /sbin/chiscsi_set_affinity.sh ; \
	    rm -rvf /sbin/cudbg_app ; rm -rf /sbin/chdebug ; \
	    ( cd chelsio_adapter_config_v4 ; ./uninstall.sh ) ; \
	    $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Uninstall) ) 

define installum
    dist=$1;\
    umversion=$2;\
    rpm --import um/RPM-GPG-KEY-Chelsio-Uwire-mgmt;\
    if [ $$dist == "RHEL6.6" ]; then \
	for rpm in cyrus-sasl-devel db4-cxx db4-devel expat-devel apr apr-util apr-devel openldap-devel apr-util-devel apr-util-ldap httpd-tools httpd httpd-manual sqlite python-simplejson mod_ssl mod_python boost-python NetworkManager-glib httpd httpd-devel; do \
	     rpm -q $$rpm &> /dev/null;\
	     if [ $$? -ne 0 ]; then \
		  rpm -ivh um/RHEL6.6/$$rpm* ;\
	     fi;\
	done;\
	for rpm in chelsio-uwire_mgmt-agent-rhel6u6 chelsio-uwire_mgmt-client-rhel6u6 chelsio-uwire_mgmt-station-rhel6u6; do \
	     rpm -q $$rpm-$$umversion &> /dev/null;\
             if [ $$? -ne 0 ]; then \
                  rpm -q $$rpm &> /dev/null;\
                  if [ $$? -ne 0 ]; then \
                      rpm -ivh um/RHEL6.6/$$rpm* ;\
                  else \
                      rpm -Uvh um/RHEL6.6/$$rpm* ;\
                      if [ $$? -ne 0 ]; then \
                          rpm -e $$rpm ;\
                          rpm -ivh um/RHEL6.6/$$rpm* ;\
                      fi ;\
                  fi;\
             else \
                  echo "Latest Version of $$rpm is already Present"; \
             fi;\
        done;\
	if [ -f /etc/httpd/conf/httpd.conf ]; then \
            sh ${PWD}/../../scripts/merge_httpd_conf.sh /etc/httpd/conf/httpd.conf ;\
	else \
	    cp -f ${PWD}/um/httpd_conf/httpd.conf /etc/httpd/conf/httpd.conf ; \
        fi;\
        rm -rf /opt/chelsio/uwire_mgmt/mgmt_station/README.txt &> /dev/null ; \
    elif [ $$dist == "SLES11sp3" ]; then \
	for rpm in sqlite3 libapr1 libapr-util1 apache2-utils-2.2.12 NetworkManager-glib ; do \
	     rpm -q $$rpm &> /dev/null; \
	     if [ $$? -ne 0 ]; then  \
		  echo "Installing $$rpm";\
		  rpm -ivh um/SLES11sp3/$$rpm* ; \
	     fi;\
	done; \
	rpm -q apache2-2.2.12 &> /dev/null ;\
	if [ $$? -ne 0 ] ; then\
	    echo "Installing Apache";\
	    rpm -ivh um/SLES11sp3/apache2-2.2.12* um/SLES11sp3/apache2-prefork* ;\
	fi;\
	rpm -q apache2-mod_python &> /dev/null ;\
        if [ $$? -ne 0 ] ; then\
	    echo "Installing Apache Mod python";\
            rpm -ivh um/SLES11sp3/apache2-mod_python* ;\
        fi;\
	for rpm in chelsio-uwire_mgmt-agent-sles11sp3 chelsio-uwire_mgmt-client-sles11sp3 chelsio-uwire_mgmt-station-sles11sp3; do \
            rpm -q $$rpm-$$umversion &> /dev/null;\
            if [ $$? -ne 0 ]; then \
                  rpm -q $$rpm &> /dev/null;\
                  if [ $$? -ne 0 ]; then \
                      rpm -ivh um/SLES11sp3/$$rpm* ;\
                  else \
                      rpm -Uvh um/SLES11sp3/$$rpm* ;\
                      if [ $$? -ne 0 ]; then \
                          rpm -e $$rpm ;\
                          rpm -ivh um/SLES11sp3/$$rpm* ;\
                      fi ;\
                  fi;\
             else \
                  echo "Latest Version of $$rpm is already Present"; \
            fi;\
        done;\
        if [ -f /etc/apache2/httpd.conf ]; then \
            sh ${PWD}/../../scripts/merge_httpd_conf.sh /etc/apache2/httpd.conf ;\
        else \
            cp -f ${PWD}/um/SLES11sp3/apache_conf/httpd.conf /etc/apache2/httpd.conf ; \
        fi;\
	for file in default-server.conf ssl-global.conf listen.conf ; do\
	    if [ -f /etc/apache2/$$file ]; then \
		mv -f /etc/apache2/$$file /etc/apache2/bak_$$file ;\
	    fi;\
	    cp -f ${PWD}/um/SLES11sp3/apache_conf/$$file /etc/apache3/$$file ; \
	done;\
	if [ -f /etc/apache2/vhosts.d/vhost-ssl.conf ]; then\
	    mv -f /etc/apache2/vhosts.d/vhost-ssl.conf /etc/apache2/vhosts.d/bak_vhost-ssl.conf ;\
	fi;\
        cp -f ${PWD}/um/SLES11sp3/apache_conf/vhosts.d/vhost-ssl.conf /etc/apache2/vhosts.d/vhost-ssl.conf ; \
	if [ -f /etc/apache2/sysconfig.d/loadmodule.conf ]; then\
	     mv -f /etc/apache2/sysconfig.d/loadmodule.conf /etc/apache2/sysconfig.d/bak_loadmodule.conf;\
        fi;\
        cp -f ${PWD}/um/SLES11sp3/apache_conf/sysconfig.d/loadmodule.conf /etc/apache2/sysconfig.d/loadmodule.conf ; \
	rm -rf /opt/chelsio/uwire_mgmt/mgmt_station/README.txt &> /dev/null ; \
    fi
endef

define uninstallum
    dist=$1;\
    um_rpms="$(shell rpm -qa | grep uwire)";\
    for rpm in $$um_rpms; do \
	rpm -e $$rpm ; \
    done;\
    if [ -f /etc/httpd/conf/httpd_bak ]; then \
	mv -f /etc/httpd/conf/httpd_bak /etc/httpd/conf/httpd.conf ;\
    fi; \
    if [ -f /etc/apache2/httpd_bak ]; then \
        mv -f /etc/apache2/httpd_bak /etc/apache2/httpd.conf ;\
    fi; \
    if [ $$dist == "SLES11sp3" ]; then \
	for file in httpd.conf default-server.conf ssl-global.conf listen.conf ; do\
	    if [ -f /etc/apache2/bak_$$file ]; then \
		rm -f /etc/apache2/$$file ;\
		mv -f /etc/apache2/bak_$$file /etc/apache2/$$file ;\
	    fi;\
	done;\
	if [ -f /etc/apache2/sysconfig.d/bak_loadmodule.conf ]; then \
	    mv -f /etc/apache2/sysconfig.d/bak_loadmodule.conf /etc/apache2/sysconfig.d/loadmodule.conf ;\
	fi;\
	if [ -f /etc/apache2/vhosts.d/bak_vhost-ssl.conf ]; then\
	   mv -f /etc/apache2/vhosts.d/bak_vhost-ssl.conf /etc/apache2/vhosts.d/vhost-ssl.conf;\
	fi;\
   fi
endef

define logtemp
echo -e "$1\t\t$2\t\t$3\t\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\t\tSuccessful" >> $(logpath)/temp.log ;
endef
