#!/bin/sh

echo "installing wechselbalg.der to the mok (machine owner key) manager"
echo "you need to have MokManger.efi in your EFI partition. Should appear below:"
sudo find /boot -name MokManager.efi

echo "importing wechselbalg.der to the mok manager, please remember your password as you must enter it during reboot!"
mokutil --import wechselbalg.der
