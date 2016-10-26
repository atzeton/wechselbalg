#!/bin/sh

error=0

#echo "[file hiding] checking file hiding functionalitiy"

#echo "[file hiding] creating file-to-hide"
echo "this is a hidden file" > file-to-hide

#echo "[file hiding] checking it's existance"
if [ $(ls -l | grep file-to-hide | wc -l) != "1" ]; then
	echo "error: file-to-hide creation failed"
	error=1
fi

#echo "[file hiding] loading wechselbalg"
sudo insmod ../bin/wechselbalg.ko hidden_files=file-to-hide


#echo "[file hiding] checking if file is still visible"
if [ $(ls -l | grep file-to-hide | wc -l) != "0" ]; then
	echo "error: file-to-hide is still visible"
	error=1
fi

#echo "[file hiding] unloading wechselbalg"
sudo rmmod wechselbalg

#echo "[file hiding] deleting file-to-hide"
rm -f file-to-hide

if [ "$error" -eq 1 ]; then
	echo "[file hiding] failed"
else 
	echo "[file hiding] successfull"
fi
