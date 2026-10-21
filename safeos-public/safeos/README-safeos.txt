SafeOS source layout (the OS shows its own README to the user, so this file has another name)

safeos/                    xv6's own files, even where we changed them: the kernel, mkfs, the user library,
                           init, sh, and xv6's programs (cat echo grep kill ln ls mkdir rm wc zombie forktest
                           stressfs usertests). Our kernel files are here too, because they are compiled into
                           the kernel: resource.c resource.h pskernel.c psinfo.h mempool.h, and the build
                           tools providers.list and genreg.pl. The Owner code is in ../root.
safeos/ORIG/               kept for copies of xv6 originals
safeos/utilities/          programs xv6 did not have: ps pwd time shutdown rmdir touch head cp mv more
safeos/testtools/          the demos (hello helloagain deadloop deadloopagain), the tests (guardtest killtest
                           regtest fpuleak lockstress, safeostests.main which makes safeostests) and test
                           programs (slowprint cpubound preempttest grptest forkbomb regdemo)
safeos/testtools/bundles/  the bundles staged in /inbox: testapp.c, the two manifest templates, genbad.sh

Built files (_name, *.o, *.asm, *.sym) stay in safeos/. So do generated sources: preinstalled.c, safeostests.c,
testagent.c, the *.manifest.txt files and bad_*.txt. make clean removes them.
