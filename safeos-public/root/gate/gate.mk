# Owner-Mode gate, included by the xv6 tree's Makefile.
vpath %.c ../root/gate
vpath %.c ../root/common
vpath %.S ../root/gate
CPPFLAGS += -I. -I../root/common -I../root/gate
ROOT_WINDOW ?= 30
ROOT_SETUP ?= 60
CFLAGS += -DROOT_WINDOW_SECS=$(ROOT_WINDOW) -DROOT_SETUP_SECS=$(ROOT_SETUP)
OBJS += rootgate.o rootio.o sha256.o rootpass.o

chain: ../root/gate/chainstart.S ../root/gate/chainmain.c
	$(CC) $(CFLAGS) -fno-pic -nostdinc -I. -c ../root/gate/chainstart.S
	$(CC) $(CFLAGS) -fno-pic -O -nostdinc -I. -c ../root/gate/chainmain.c
	$(LD) $(LDFLAGS) -N -e start -Ttext 0x7000 -o chain.out chainstart.o chainmain.o
	$(OBJCOPY) -S -O binary -j .text chain.out chain
	$(OBJDUMP) -S chain.out > chain.asm
