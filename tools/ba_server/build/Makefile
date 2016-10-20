#############################################################################
#
# 	Main makefile for the bypass adapter
#
#############################################################################

#############################################################################
#
# 	set Makefile local variables
#
#############################################################################

# Root directory of the source tree.
export ROOT_DIR=$(shell cd ../../..; pwd )

#
# set defaults for platform and architecture
#
ifeq ($(PLATFORM), )
	PLATFORM=t4
endif

export PLATFORM
export ARCH=i386

export BA_BLD_DIR=$(pwd)/build/$(PLATFORM)
export BA_SRC_DIR=$(pwd)/src

BUILD_TARGETS = ba
INSTALL_TARGETS = ba_install

#############################################################################
#
#	main targets
#
#############################################################################

all: build_all

# build all components
build_all: $(BUILD_TARGETS)

# install all components
install_all: $(INSTALL_TARGETS)

install: install_all

uninstall: ba_uninstall

# remove build
build_clean:
	@rm -rf $(BA_BLD_DIR)

# remove build and install
clean: build_clean

#############################################################################
#
#	build
#
#############################################################################

ba_clean:
	@rm -rf $(BA_BLD_DIR)/lib
	@rm -rf $(BA_BLD_DIR)/ba

ba: 	$(BA_SRC_DIR)/Makefile
	@mkdir -p $(BA_BLD_DIR)
	@BUILD_SRC=$(BA_SRC_DIR) make -C $(BA_BLD_DIR) \
		-f $(BA_SRC_DIR)/Makefile all

#############################################################################
#
#	install
#
#############################################################################

ba_install: 
	install -m 755 $(BA_BLD_DIR)/ba_server $(PREFIX)/sbin
	install -m 755 $(BA_BLD_DIR)/ba_client $(PREFIX)/sbin
	ln -f $(PREFIX)/sbin/ba_client $(PREFIX)/sbin/redirect
	ln -f $(PREFIX)/sbin/ba_client $(PREFIX)/sbin/bypass
	gzip -c $(BA_SRC_DIR)/bypass.8 > bypass.8.gz
	gzip -c $(BA_SRC_DIR)/redirect.8 > redirect.8.gz
	@if [ -d $(PREFIX)/usr/share/man ]; then \
		install -m 444 bypass.8.gz $(PREFIX)/usr/share/man/man8;\
		install -m 444 redirect.8.gz $(PREFIX)/usr/share/man/man8;\
	elif [ -d $(PREFIX)/usr/man ]; then\
		install -m 444 bypass.8.gz $(PREFIX)/usr/man/man8;\
		install -m 444 redirect.8.gz $(PREFIX)/usr/man/man8;\
	fi
	@/bin/rm -f bypass.8.gz
	@/bin/rm -f redirect.8.gz
	install -m 744 ba-rc /etc/init.d/bad

#############################################################################
#
#	uninstall
#
#############################################################################

ba_uninstall: 
	rm -f $(PREFIX)/etc/init.d/bad
	rm -f $(PREFIX)/sbin/ba_server
	rm -f $(PREFIX)/sbin/ba_client
	rm -f $(PREFIX)/sbin/redirect
	rm -f $(PREFIX)/sbin/bypass
	@if [ -d $(PREFIX)/usr/share/man ]; then \
		rm -f $(PREFIX)/usr/share/man/man8/bypass.8.gz;\
		rm -f $(PREFIX)/usr/share/man/man8/redirect.8.gz;\
	elif [ -d $(PREFIX)/usr/man ]; then\
		rm -f $(PREFIX)/usr/man/man8/bypass.8.gz;\
		rm -f $(PREFIX)/usr/man/man8/redirect.8.gz;\
	fi

