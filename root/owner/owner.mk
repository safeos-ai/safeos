# Owner-Mode confirm point, included by the SafeOS kernel's Makefile.
vpath %.c ../root/owner
vpath %.c ../root/common
CPPFLAGS += -I. -I../root/owner -I../root/common
OBJS += rootconfirm.o rootfsup.o rootsvc.o rootguard.o rootrules.o sha256.o rootring1.o rootgroups.o rootkindrules.o rootregistry.o preinstalled.o
vpath %.S ../root/owner
OWNER1_CFLAGS = -fno-pic -O -nostdinc -ffreestanding -fno-builtin -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns -I. -I../root/common
ifeq ($(OWNER_FAULT_TEST),1)
OWNER1_CFLAGS += -DOWNER_FAULT_TEST
endif
owner1: ../root/owner/img/owner1start.S ../root/owner/img/owner1.c ../root/common/sha256.c ../root/common/rootpass.c ../root/common/rootblock.h
	$(CC) $(CFLAGS) $(OWNER1_CFLAGS) -c ../root/owner/img/owner1start.S -o o1_start.o
	$(CC) $(CFLAGS) $(OWNER1_CFLAGS) -c ../root/owner/img/owner1.c -o o1_main.o
	$(CC) $(CFLAGS) $(OWNER1_CFLAGS) -c ../root/common/sha256.c -o o1_sha256.o
	$(CC) $(CFLAGS) $(OWNER1_CFLAGS) -c ../root/common/rootpass.c -o o1_pass.o
	$(LD) $(LDFLAGS) -N -e owner1_start -Ttext 0 -o owner1.out o1_start.o o1_main.o o1_sha256.o o1_pass.o
	$(OBJCOPY) -S -O binary --set-section-flags .bss=alloc,load,contents -j .text -j .rodata -j .data -j .bss owner1.out owner1
# make APPS_OPEN=1 leaves /apps unprotected, so the tamper tests can run
ifeq ($(APPS_OPEN),1)
CFLAGS += -DAPPS_OPEN
endif
