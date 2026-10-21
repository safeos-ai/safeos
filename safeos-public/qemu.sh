#!/bin/sh
# Run the SafeOS dual-kernel image in QEMU.
# Usage: ./qemu.sh [cpus]       (default 2, range 1-8)
#        DEBUG=1 ./qemu.sh 2    (also log CPU resets to qemu.log, and exit on the first one)
# Quit QEMU with Ctrl-A, then x.

cd "$(dirname "$0")" || exit 1

CPUS=${1:-2}
case "$CPUS" in
  [1-8]) ;;
  *) echo "usage: $0 [cpus 1-8]" >&2; exit 1 ;;
esac

for f in build/xv6.img build/fs.img; do
  [ -f "$f" ] || { echo "missing $f - run make first" >&2; exit 1; }
done

EXTRA=""
[ -n "$DEBUG" ] && EXTRA="-no-reboot -d cpu_reset -D qemu.log"

exec qemu-system-i386 -M pc-i440fx-2.0 -nographic $EXTRA \
  -drive file=build/fs.img,index=1,media=disk,format=raw \
  -drive file=build/xv6.img,index=0,media=disk,format=raw \
  -smp "$CPUS" -m 512
