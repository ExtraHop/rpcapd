include ../../global.mk

PKG = rpcapd.tgz
INSTALLER_TARGET = install-rpcapd.sh
RPCAPD_TARGET = rpcapd
RPCAPD_DIST_DIR = wpcap/libpcap/rpcapd/rpcapd-dist
RPCAPD_FILES = \
    rpcapd-64bit-linux          \
	rpcapd.sh                   \
	rpcapd.debianinit           \
	rpcapd.sysvinit

SUBDIRS = \
	packetNtx/Dll/Project \
	wpcap/PRJ \
	wpcap/libpcap/rpcapd \

.PHONY: all
all: $(SUBDIRS)
	tar -cvf - -C $(RPCAPD_DIST_DIR) $(RPCAPD_FILES) \
	| cat extract.sh - > $(INSTALLER_TARGET)
	chmod 0755 $(INSTALLER_TARGET)

.PHONY: clean
clean: $(SUBDIRS)
	rm -f $(INSTALLER_TARGET)

.PHONY: install
install: $(SUBDIRS)
	$(INSTALL) -d install/www
	$(INSTALL) -d install/www/tools
	$(INSTALL) -m 0755 $(INSTALLER_TARGET) install/www/tools
	tar -C install -cvzf $(PACKAGES)/$(PKG) .

.PHONY: distclean
distclean: clean
	rm -rf install
	rm -f $(PACKAGES)/$(PKG)

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

