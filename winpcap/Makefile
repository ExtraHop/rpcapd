include ../../global.mk

PKG = rpcapd.tgz

SUBDIRS = \
	packetNtx/Dll/Project \
	wpcap/PRJ \
	wpcap/libpcap/rpcapd \

.PHONY: all
all: $(SUBDIRS)

.PHONY: clean
clean: $(SUBDIRS)

# none of the sub-makefiles have a separate distclean
.PHONY: distclean
distclean: clean

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

