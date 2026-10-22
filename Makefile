.PHONY: all kernels clean
all: build/xv6.img build/fs.img

kernels:
	$(MAKE) -C xv6 kernel bootblock
	$(MAKE) -C safeos kernel fs.img

build/xv6.img: kernels
	mkdir -p build
	@test $$(stat -c %s xv6/kernel) -lt $$((799*512)) || { echo "xv6 kernel would overlap the Owner block (sector 800)"; exit 1; }
	dd if=/dev/zero of=$@ count=10000
	dd if=xv6/bootblock of=$@ conv=notrunc
	dd if=xv6/kernel of=$@ seek=1 conv=notrunc
	dd if=safeos/kernel of=$@ seek=2048 conv=notrunc

build/fs.img: kernels
	mkdir -p build
	cp safeos/fs.img $@

clean:
	$(MAKE) -C xv6 clean
	$(MAKE) -C safeos clean
	rm -f build/*.img build/*.vmdk xv6/chain xv6/chain.out
