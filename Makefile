obj-m += nvidia-pidns.o

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build
PWD := $(shell pwd)

all:
	rm -rf nvidia-pidns.ko
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:  all
	dmesg -C
	insmod nvidia-pidns.ko
	lsmod | grep pidns
	modinfo nvidia-pidns.ko
	nvidia-smi
	dmesg

uninstall:
	rmmod nvidia-pidns.ko
	lsmod | grep pidns
	modinfo nvidia-pidns.ko
	dmesg

test:
	clear
	dmesg -C
	docker run --rm -it -e NVIDIA_VISIBLE_DEVICES=0 --name=tf -v `pwd`:/tf registry.cn-hangzhou.aliyuncs.com/acejilam/tensorflow:2.14.0-gpu  python3 /tf/test.py
	dmesg
