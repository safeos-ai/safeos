#!/bin/sh
# Inspect or reset the Owner block in build/xv6.img (QEMU runs).
# Usage: ./rootctl.sh show | reset | breaksafeos | fixsafeos
cd "$(dirname "$0")" || exit 1
IMG=${IMG:-build/xv6.img}
case "$1" in
  show)
    set -- $(dd if=$IMG bs=512 skip=800 count=1 2>/dev/null | od -v -A n -t u4 -N 24)
    case "$3" in 0) CN=xv6 ;; 1) CN=safeos ;; *) CN="?" ;; esac
    case "$4" in 0) SN=none ;; 1) SN=handover ;; 2) SN=booting ;; 3) SN=confirmed ;; *) SN="?" ;; esac
    printf 'magic    %08x\n' $1
    printf 'version  %d\n' $2
    printf 'chosen   %d (%s)\n' $3 $CN
    printf 'stage    %d (%s)\n' $4 $SN
    printf 'failures %d\n' $5
    printf 'checksum %08x\n' $6
    ;;
  reset)
    dd if=/dev/zero of=$IMG bs=512 seek=800 count=1 conv=notrunc 2>/dev/null
    echo "Owner block cleared: the next boot treats it as blank (chooses SafeOS)"
    ;;
  breaksafeos)
    ENTRY=$(readelf -hW safeos/kernel | awk '/Entry point/ {print $NF}')
    OFF=$(readelf -lW safeos/kernel | while read type off va pa fs ms rest; do
      [ "$type" = LOAD ] || continue
      if [ $((ENTRY)) -ge $((pa)) ] && [ $((ENTRY)) -lt $((pa + fs)) ]; then
        echo $((off + ENTRY - pa)); break
      fi
    done)
    [ -n "$OFF" ] || { echo "cannot find the entry point in safeos/kernel" >&2; exit 1; }
    printf '\353\376' | dd of=$IMG bs=1 seek=$((2048*512 + OFF)) conv=notrunc 2>/dev/null
    echo "patched the SafeOS entry point (file offset $OFF) with 'jmp .'"
    ;;
  fixsafeos)
    dd if=safeos/kernel of=$IMG bs=512 seek=2048 conv=notrunc 2>/dev/null
    echo "SafeOS kernel restored at sector 2048"
    ;;
  *)
    echo "usage: $0 show | reset | breaksafeos | fixsafeos" >&2; exit 1 ;;
esac
