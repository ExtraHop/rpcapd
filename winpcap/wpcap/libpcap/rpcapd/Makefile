################################
# Makefile for the remote daemon
################################

LINUXCC = gcc
WINCC   = x86_64-w64-mingw32-gcc  # 64-bit

CFLAGS      = -DHAVE_REMOTE -DHAVE_SNPRINTF -D_GNU_SOURCE=1 -O3 -g
LINUXCFLAGS = -pthread
WINCFLAGS   = -DHAVE_STRUCT_TIMESPEC

#flags for debugging: -D_DEBUG -g -Wall

INCLUDE    = -I../
WININCLUDE = -I../Win32/Include -I../../../Common -Iwin32-pthreads

LINUXLIB = -lpcap -lcrypt -static
WINLIB   = -lwpcap -lpthreadGC2 -lpacket -lws2_32

LINUXLIBPATH = -L../
WINLIBPATH   = -L../../lib -Lwin32-pthreads \
               -L../../../packetNtx/Dll/Project

# Files that are needed to compile this project
FILES = rpcapd.o daemon.o utils.o fileconf.o pcap-remote.o sockutils.o pcap-new.o
WINFILES = win32-svc.o

LINUXTARGET = rpcapd
WINTARGET   = rpcapd.exe

# XXX: this is awful...I think this is why they invented autotools 25 years ago.
ifeq ($(PLATFORM), windows)
    CC = $(WINCC)
    FILES += $(WINFILES)
    CFLAGS += $(WINCFLAGS)
    INCLUDE += $(WININCLUDE)
    LIB += $(WINLIB)
    LIBPATH += $(WINLIBPATH)
    TARGET = $(WINTARGET)
else
    CC = $(LINUXCC)
    FILES += $(LINUXFILES)
    CFLAGS += $(LINUXCFLAGS)
    INCLUDE += $(LINUXINCLUDE)
    LIB += $(LINUXLIB)
    LIBPATH += $(LINUXLIBPATH)
    TARGET = $(LINUXTARGET)
endif


# Makefile syntax:
# Project name : dependencies
#  command line

$(TARGET): $(FILES)
	$(CC) $(CFLAGS) $(INCLUDE) $(LIBPATH) -o $(TARGET) $(FILES) $(LIB)

win32-svc.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c win32-svc.c

rpcapd.o: rpcapd.c
	$(CC) $(CFLAGS) $(INCLUDE) -c rpcapd.c

daemon.o: daemon.c
	$(CC) $(CFLAGS) $(INCLUDE) -c daemon.c

utils.o: utils.c
	$(CC) $(CFLAGS) $(INCLUDE) -c utils.c

fileconf.o: fileconf.c
	$(CC) $(CFLAGS) $(INCLUDE) -c fileconf.c

sockutils.o: ../sockutils.c
	$(CC) $(CFLAGS) $(INCLUDE) -c ../sockutils.c

pcap-remote.o: ../pcap-remote.c
	$(CC) $(CFLAGS) $(INCLUDE) -c ../pcap-remote.c

pcap-new.o: ../pcap-new.c
	$(CC) $(CFLAGS) $(INCLUDE) -c ../pcap-new.c

clean:
	rm -f *.o
	rm rpcapd

