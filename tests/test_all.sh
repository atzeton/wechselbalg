#!/bin/sh

test -f ../bin/wechselbalg.ko
if [ $? != 0 ]; then
	echo "error: wechselbalg.ko not existing, did you compile it yet?"
	exit
fi


echo "[all] launching all tests..."

./test_root_shell.sh
./test_file_hiding.sh
./test_process_hiding.sh
./test_netstat.sh
