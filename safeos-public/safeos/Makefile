OBJS = \
	bio.o\
	console.o\
	exec.o\
	file.o\
	fs.o\
	ide.o\
	ioapic.o\
	kalloc.o\
	kbd.o\
	lapic.o\
	log.o\
	main.o\
	mp.o\
	picirq.o\
	pipe.o\
	proc.o\
	pskernel.o\
	resource.o\
	sleeplock.o\
	spinlock.o\
	string.o\
	swtch.o\
	syscall.o\
	sysfile.o\
	sysproc.o\
	trapasm.o\
	trap.o\
	uart.o\
	vectors.o\
	vm.o\

# Cross-compiling (e.g., on Mac OS X)
# TOOLPREFIX = i386-jos-elf

# Using native tools (e.g., on X86 Linux)
#TOOLPREFIX = 

# Try to infer the correct TOOLPREFIX if not set
ifndef TOOLPREFIX
TOOLPREFIX := $(shell if i386-jos-elf-objdump -i 2>&1 | grep '^elf32-i386$$' >/dev/null 2>&1; \
	then echo 'i386-jos-elf-'; \
	elif objdump -i 2>&1 | grep 'elf32-i386' >/dev/null 2>&1; \
	then echo ''; \
	else echo "***" 1>&2; \
	echo "*** Error: Couldn't find an i386-*-elf version of GCC/binutils." 1>&2; \
	echo "*** Is the directory with i386-jos-elf-gcc in your PATH?" 1>&2; \
	echo "*** If your i386-*-elf toolchain is installed with a command" 1>&2; \
	echo "*** prefix other than 'i386-jos-elf-', set your TOOLPREFIX" 1>&2; \
	echo "*** environment variable to that prefix and run 'make' again." 1>&2; \
	echo "*** To turn off this error, run 'gmake TOOLPREFIX= ...'." 1>&2; \
	echo "***" 1>&2; exit 1; fi)
endif

# If the makefile can't find QEMU, specify its path here
# QEMU = qemu-system-i386

# Try to infer the correct QEMU
ifndef QEMU
QEMU = $(shell if which qemu > /dev/null; \
	then echo qemu; exit; \
	elif which qemu-system-i386 > /dev/null; \
	then echo qemu-system-i386; exit; \
	elif which qemu-system-x86_64 > /dev/null; \
	then echo qemu-system-x86_64; exit; \
	else \
	qemu=/Applications/Q.app/Contents/MacOS/i386-softmmu.app/Contents/MacOS/i386-softmmu; \
	if test -x $$qemu; then echo $$qemu; exit; fi; fi; \
	echo "***" 1>&2; \
	echo "*** Error: Couldn't find a working QEMU executable." 1>&2; \
	echo "*** Is the directory containing the qemu binary in your PATH" 1>&2; \
	echo "*** or have you tried setting the QEMU variable in Makefile?" 1>&2; \
	echo "***" 1>&2; exit 1)
endif

CC = $(TOOLPREFIX)gcc
AS = $(TOOLPREFIX)gas
LD = $(TOOLPREFIX)ld
OBJCOPY = $(TOOLPREFIX)objcopy
OBJDUMP = $(TOOLPREFIX)objdump
CFLAGS = -fno-pic -static -fno-builtin -fno-strict-aliasing -O2 -Wall -MD -ggdb -m32 -Werror -Wno-infinite-recursion -Wno-array-bounds -fno-omit-frame-pointer
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)
ASFLAGS = -m32 -gdwarf-2 -Wa,-divide
# FreeBSD ld wants ``elf_i386_fbsd''
LDFLAGS += -m $(shell $(LD) -V | grep elf_i386 2>/dev/null | head -n 1)

# Disable PIE when possible (for Ubuntu 16.10 toolchain)
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
CFLAGS += -fno-pie -no-pie
endif
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]nopie'),)
CFLAGS += -fno-pie -nopie
endif

xv6.img: bootblock kernel
	dd if=/dev/zero of=xv6.img count=10000
	dd if=bootblock of=xv6.img conv=notrunc
	dd if=kernel of=xv6.img seek=1 conv=notrunc

xv6memfs.img: bootblock kernelmemfs
	dd if=/dev/zero of=xv6memfs.img count=10000
	dd if=bootblock of=xv6memfs.img conv=notrunc
	dd if=kernelmemfs of=xv6memfs.img seek=1 conv=notrunc

bootblock: bootasm.S bootmain.c
	$(CC) $(CFLAGS) -fno-pic -O -nostdinc -I. -c bootmain.c
	$(CC) $(CFLAGS) -fno-pic -nostdinc -I. -c bootasm.S
	$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 -o bootblock.o bootasm.o bootmain.o
	$(OBJDUMP) -S bootblock.o > bootblock.asm
	$(OBJCOPY) -S -O binary -j .text bootblock.o bootblock
	./sign.pl bootblock

entryother: entryother.S
	$(CC) $(CFLAGS) -fno-pic -nostdinc -I. -c entryother.S
	$(LD) $(LDFLAGS) -N -e start -Ttext 0x7000 -o bootblockother.o entryother.o
	$(OBJCOPY) -S -O binary -j .text bootblockother.o entryother
	$(OBJDUMP) -S bootblockother.o > entryother.asm

initcode: initcode.S
	$(CC) $(CFLAGS) -nostdinc -I. -c initcode.S
	$(LD) $(LDFLAGS) -N -e start -Ttext 0 -o initcode.out initcode.o
	$(OBJCOPY) -S -O binary initcode.out initcode
	$(OBJDUMP) -S initcode.o > initcode.asm

include ../root/owner/owner.mk

kernel: $(OBJS) entry.o entryother initcode owner1 kernel.ld
	$(LD) $(LDFLAGS) -T kernel.ld -o kernel entry.o $(OBJS) -b binary initcode entryother owner1
	$(OBJDUMP) -S kernel > kernel.asm
	$(OBJDUMP) -t kernel | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > kernel.sym

# kernelmemfs is a copy of kernel that maintains the
# disk image in memory instead of writing to a disk.
# This is not so useful for testing persistent storage or
# exploring disk buffering implementations, but it is
# great for testing the kernel on real hardware without
# needing a scratch disk.
MEMFSOBJS = $(filter-out ide.o,$(OBJS)) memide.o
kernelmemfs: $(MEMFSOBJS) entry.o entryother initcode kernel.ld fs.img
	$(LD) $(LDFLAGS) -T kernel.ld -o kernelmemfs entry.o  $(MEMFSOBJS) -b binary initcode entryother fs.img
	$(OBJDUMP) -S kernelmemfs > kernelmemfs.asm
	$(OBJDUMP) -t kernelmemfs | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > kernelmemfs.sym

tags: $(OBJS) entryother.S _init
	etags *.S *.c

vectors.S: vectors.pl
	./vectors.pl > vectors.S

# Where the user programs are. xv6's own are in this directory. The ones xv6 did not have are in utilities/, the demos
# and tests are in testtools/, and the test bundles are in testtools/bundles/. make finds the sources there, and the
# built _name files stay in this directory.
vpath %.c utilities testtools testtools/bundles
vpath %.main testtools
vpath %.in testtools/bundles
vpath %.sh testtools/bundles
DEMOSRC = testtools/hello.c testtools/helloagain.c testtools/deadloop.c testtools/deadloopagain.c

ULIB = ulib.o usys.o printf.o umalloc.o

_%: %.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $@ $^
	$(OBJDUMP) -S $@ > $*.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $*.sym

_forktest: forktest.o $(ULIB)
	# forktest has less library code linked in - needs to be small
	# in order to be able to max out the proc table.
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o _forktest forktest.o ulib.o usys.o
	$(OBJDUMP) -S _forktest > forktest.asm

mkfs: mkfs.c fs.h
	gcc -Werror -Wno-infinite-recursion -Wno-array-bounds -Wall -o mkfs mkfs.c

# Prevent deletion of intermediate files, e.g. cat.o, after first build, so
# that disk image changes after first build are persistent until clean.  More
# details:
# http://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
.PRECIOUS: %.o

# The programs of every build: the xv6 commands, our own utilities, the four demos, and safeostests (the five tests in one program)
UPROGS_COMMON = \
        _cat \
        _deadloop \
        _deadloopagain \
        _echo \
        _forktest \
        _grep \
        _hello \
        _helloagain \
        _init \
        _kill \
        _ln \
        _ls \
        _ps \
        _time \
        _shutdown \
        _mkdir \
        _rm \
        _sh \
        _stressfs \
        _usertests \
        _wc \
        _zombie \
        _pwd \
        _rmdir \
        _touch \
        _head \
        _cp \
        _mv \
        _more \
        _safeostests

# The programs that only a DEV_PROGRAMS=1 build puts in /bin: the five tests on their own, and test programs
UPROGS_DEV = _guardtest _killtest _regtest _fpuleak _lockstress _slowprint _cpubound _preempttest _grptest _forkbomb _regdemo

UPROGS = $(UPROGS_COMMON) $(if $(filter 1,$(DEV_PROGRAMS)),$(UPROGS_DEV))

# The preinstalled programs: the SHA-256 of each built program, made into preinstalled.c
.DELETE_ON_ERROR:
.devflag: FORCE
	@echo "$(DEV_PROGRAMS)" | cmp -s - $@ || echo "$(DEV_PROGRAMS)" > $@
FORCE:
preinstalled.c: genreg.pl providers.list .devflag $(UPROGS)
	perl genreg.pl $(if $(filter 1,$(DEV_PROGRAMS)),--dev,) providers.list > preinstalled.c

# The test bundle's manifest: the template plus the hash of its program. The bundles that the installer must refuse come from genbad.sh.
testapp.manifest.txt: testapp.manifest.in _testapp
	cp $< $@
	echo "commands: testapp $$(sha256sum _testapp | cut -d' ' -f1)" >> $@
	@echo "testapp manifest sha256: $$(sha256sum $@ | cut -d' ' -f1)"

.badbundles: genbad.sh _testapp
	sh $<
	touch $@

# testagent: the same program as testapp under another name, installed as an agent
testagent.c: testapp.c
	sed -e 's/testapp/testagent/g' -e 's/an installed app/an installed agent/' $< > $@

testagent.manifest.txt: testagent.manifest.in _testagent
	cp $< $@
	echo "commands: testagent $$(sha256sum _testagent | cut -d' ' -f1)" >> $@
	@echo "testagent manifest sha256: $$(sha256sum $@ | cut -d' ' -f1)"

# safeostests: the five tests in one program. Each test's main is renamed, and safeostests.main runs them.
safeostests.c: guardtest.c killtest.c regtest.c fpuleak.c lockstress.c safeostests.main
	( echo "// safeostests.c: made by the Makefile from the five tests and safeostests.main. Do not edit."; \
	  echo '#include "types.h"'; echo '#include "stat.h"'; echo '#include "user.h"'; echo '#include "fcntl.h"'; \
	  for t in guardtest killtest regtest fpuleak lockstress; do \
	    echo "// ---- $$t ----"; \
	    sed -e '/^#include/d' -e "s/^main(/$${t}_main(/" testtools/$$t.c; \
	  done; \
	  cat testtools/safeostests.main ) > $@

# The bundles that the installer must refuse are only in a DEV_PROGRAMS=1 build
BADBUNDLES = -b badhash manifest.txt=bad_badhash.txt badhash=_testapp -b badkind manifest.txt=bad_badkind.txt badkind=_testapp -b baddeps manifest.txt=bad_baddeps.txt baddeps=_testapp -b badreq manifest.txt=bad_badreq.txt badreq=_testapp -b bigask manifest.txt=bad_bigask.txt bigask=_testapp -b bigout manifest.txt=bad_bigout.txt bigout=_testapp -b oldlimit manifest.txt=bad_oldlimit.txt oldlimit=_testapp -b twocmd manifest.txt=bad_twocmd.txt twocmd=_testapp -b nogoal manifest.txt=bad_nogoal.txt nogoal=_testapp -b extrafile manifest.txt=bad_extrafile.txt extrafile=_testapp stray=README -b echo manifest.txt=bad_echo.txt echo=_testapp
ifeq ($(DEV_PROGRAMS),1)
BUNDLEARGS = $(BADBUNDLES)
BUNDLEDEPS = .badbundles
endif


fs.img: mkfs README $(DEMOSRC) $(UPROGS) _testapp testapp.manifest.txt $(BUNDLEDEPS) .devflag _testagent testagent.manifest.txt
	./mkfs fs.img README $(DEMOSRC) $(UPROGS) -b testapp manifest.txt=testapp.manifest.txt testapp=_testapp -b testagent manifest.txt=testagent.manifest.txt testagent=_testagent $(BUNDLEARGS)

-include *.d

clean: 
	rm -f *.tex *.dvi *.idx *.aux *.log *.ind *.ilg \
	*.o *.d *.asm *.sym vectors.S bootblock entryother \
	initcode initcode.out kernel xv6.img fs.img kernelmemfs \
	xv6memfs.img mkfs .gdbinit owner1 owner1.out \
	preinstalled.c safeostests.c testagent.c *.manifest.txt bad_*.txt .badbundles _testapp _testagent \
	$(UPROGS_COMMON) $(UPROGS_DEV)

# make a printout
FILES = $(shell grep -v '^\#' runoff.list)
PRINT = runoff.list runoff.spec README $(DEMOSRC) toc.hdr toc.ftr $(FILES)

xv6.pdf: $(PRINT)
	./runoff
	ls -l xv6.pdf

print: xv6.pdf

# run in emulators

bochs : fs.img xv6.img
	if [ ! -e .bochsrc ]; then ln -s dot-bochsrc .bochsrc; fi
	bochs -q

# try to generate a unique GDB port
GDBPORT = $(shell expr `id -u` % 5000 + 25000)
# QEMU's gdb stub command line changed in 0.11
QEMUGDB = $(shell if $(QEMU) -help | grep -q '^-gdb'; \
	then echo "-gdb tcp::$(GDBPORT)"; \
	else echo "-s -p $(GDBPORT)"; fi)
ifndef CPUS
CPUS := 2
endif
QEMUOPTS = -drive file=fs.img,index=1,media=disk,format=raw -drive file=xv6.img,index=0,media=disk,format=raw -smp $(CPUS) -m 512 $(QEMUEXTRA)

qemu: fs.img xv6.img
	$(QEMU) -serial mon:stdio $(QEMUOPTS)

qemu-memfs: xv6memfs.img
	$(QEMU) -drive file=xv6memfs.img,index=0,media=disk,format=raw -smp $(CPUS) -m 256

qemu-nox: fs.img xv6.img

qemu-nox-smp: fs.img xv6.img
	$(QEMU) -M pc-i440fx-2.0 -nographic $(QEMUOPTS)
	$(QEMU) -nographic $(QEMUOPTS)

.gdbinit: .gdbinit.tmpl
	sed "s/localhost:1234/localhost:$(GDBPORT)/" < $^ > $@

qemu-gdb: fs.img xv6.img .gdbinit
	@echo "*** Now run 'gdb'." 1>&2
	$(QEMU) -serial mon:stdio $(QEMUOPTS) -S $(QEMUGDB)

qemu-nox-gdb: fs.img xv6.img .gdbinit
	@echo "*** Now run 'gdb'." 1>&2
	$(QEMU) -nographic $(QEMUOPTS) -S $(QEMUGDB)

# CUT HERE
# prepare dist for students
# after running make dist, probably want to
# rename it to rev0 or rev1 or so on and then
# check in that version.

EXTRA=\
	mkfs.c ulib.c user.h cat.c echo.c forktest.c grep.c kill.c\
	ln.c ls.c mkdir.c rm.c stressfs.c usertests.c wc.c zombie.c\
	printf.c umalloc.c\
	README hello.c helloagain.c deadloop.c deadloopagain.c dot-bochsrc *.pl toc.* runoff runoff1 runoff.list\
	.gdbinit.tmpl gdbutil\

dist:
	rm -rf dist
	mkdir dist
	for i in $(FILES); \
	do \
		grep -v PAGEBREAK $$i >dist/$$i; \
	done
	sed '/CUT HERE/,$$d' Makefile >dist/Makefile
	echo >dist/runoff.spec
	cp $(EXTRA) dist

dist-test:
	rm -rf dist
	make dist
	rm -rf dist-test
	mkdir dist-test
	cp dist/* dist-test
	cd dist-test; $(MAKE) print
	cd dist-test; $(MAKE) bochs || true
	cd dist-test; $(MAKE) qemu

# update this rule (change rev#) when it is time to
# make a new revision.
tar:
	rm -rf /tmp/xv6
	mkdir -p /tmp/xv6
	cp dist/* dist/.gdbinit.tmpl /tmp/xv6
	(cd /tmp; tar cf - xv6) | gzip >xv6-rev10.tar.gz  # the next one will be 10 (9/17)

.PHONY: dist-test dist
