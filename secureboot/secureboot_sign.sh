#!/bin/sh
# Source: http://gorka.eguileor.com/vbox-vmware-in-secureboot-linux-2016-update/

echo 'signing ../bin/wechselbalg.ko'

sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 ./wechselbalg.priv ./wechselbalg.der ../bin/wechselbalg.ko
