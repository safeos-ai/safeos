#!/bin/sh
# genbad.sh: the manifests of the bundles that the installer must refuse. Each program is a copy of _testapp,
# so every one has the right hash, and each manifest has one defect.
h=$(sha256sum _testapp | cut -d' ' -f1)
z=0000000000000000000000000000000000000000000000000000000000000000
printf 'name: badhash\nkind: app\ngoal: wrong program hash\ncommands: badhash %s\n' "$z" > bad_badhash.txt
printf 'name: badkind\nkind: utilities\ngoal: wrong kind\ncommands: badkind %s\n' "$h" > bad_badkind.txt
printf 'name: baddeps\nkind: app\ngoal: missing dependency\ncommands: baddeps %s\ndeps: ls, nosuchprog\n' "$h" > bad_baddeps.txt
printf 'name: badreq\nkind: app\ngoal: bad request\ncommands: badreq %s\nrequires: cputime 0\n' "$h" > bad_badreq.txt
printf 'name: bigask\nkind: app\ngoal: asks for too much cpu\ncommands: bigask %s\nrequires: cputime 999999\n' "$h" > bad_bigask.txt
printf 'name: bigout\nkind: app\ngoal: asks for too many writes\ncommands: bigout %s\nrequires: stdout 999999\n' "$h" > bad_bigout.txt
printf 'name: oldlimit\nkind: app\ngoal: uses the old limit key\ncommands: oldlimit %s\nlimit cputime 500 process kill\n' "$h" > bad_oldlimit.txt
printf 'name: twocmd\nkind: app\ngoal: two commands\ncommands: twocmd %s; x\n' "$h" > bad_twocmd.txt
printf 'name: nogoal\nkind: app\ncommands: nogoal %s\n' "$h" > bad_nogoal.txt
printf 'name: extrafile\nkind: app\ngoal: a third file\ncommands: extrafile %s\n' "$h" > bad_extrafile.txt
printf 'name: echo\nkind: app\ngoal: collides with echo\ncommands: echo %s\n' "$h" > bad_echo.txt
