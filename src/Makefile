obj-m += wechselbalg.o
ccflags-y += -Wno-unused-function

all:
	make -s -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp wechselbalg.ko ../bin/

clean:
	make -s -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm ../bin/wechselbalg.ko
