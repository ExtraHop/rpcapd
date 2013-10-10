include vars.mk

ifdef WINCC_VERSION
SUBDIRS += win32-pthreads
endif

SUBDIRS += \
	winpcap \


.PHONY: all
all: $(SUBDIRS)

.PHONY: clean
clean: $(SUBDIRS)

.PHONY: distclean
distclean: clean

.PHONY: install
install: $(SUBDIRS)

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
