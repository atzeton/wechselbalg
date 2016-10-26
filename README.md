## Wechselbalg

Wechselbalg (German for changeling) is a educational linux kernel-land rootkit.

## wechselbalg.ko

Wechselbalg is a educational kernel-land rootkit which currently supports the following functionality:

* hiding files
* hididng processes
* being not visible to lsmod
* giving root to a process that receives the magic signal
* verbosity: log all things (in case of a crash, whatever)

## get_root

Only used for privilege expansion. Call it when wechselbalg is planted, it will give you a root shell.

## Build & Run

Software requirements: linux kernel headers

**Important**: Never deploy wechselbalg in production systems! Also, use it at your own risk.

1. Run `make` in `src/` to build the kernel module. If the build process was successfull, the kernel module is copied to `bin/`
2. Run `make` in `get_root/` to build the get_root root shell utility
3. In case you're using UEFI Secureboot check out the Secureboot section
5. Launch it (as root) with `insmod wechselbalg.ko <arguments>`, for arguments check the usage section

## Usage: only at your own risk

Wechselbalg supports different module arguments:

* `hidden_files="file1.txt,userland.sh,..."`
* `hidden_ports=80,31337,443,65500,...`
* `hidden_procs="userland.sh,mytool,..."`
* `hide=(0|1)`
* `verbose=(0|1)`

Example: `sudo insmod bin/wechselbalg.ko hidden_files="hidden.file" hidden_procs="userland-rootkit,1337shell"`

WARNING: Cannot be unloaded if invisible!

## Secureboot How-To
Problem: UEFI Secure Boot causes

> `modprobe: ERROR: could not insert 'wechselbalg': Required key not available` 

which is caused by the MOK system (machine owner keys). Basically, a new key must be generated and added to the systems machine owner keys. Later, this key is used to sign the given kernel module which is then allowed to be loaded. For further information take a look at `mokutil`, `keyctl` and the website below.

To cope with this issue wechselbalg comes with a bunch of scripts in `secureboot/`.

1. Generate the key using `secureboot_generate_key.sh`, key is saved as wechselbalg.priv and wechselbalg.der
2. Install the key to the MOK with `secureboot_install_to_mok.sh`. This requires the MokManager on in your EFI system and causes a reboot. **Remember the password!**
3. Check if the key installation was completed successfully with `secureboot_postinstall.sh`
4. Sign your `wechselbalg.ko` kernel module every time after compilation using `secureboot_sign.sh`
5. Profit o/


Source: http://gorka.eguileor.com/vbox-vmware-in-secureboot-linux-2016-update/

Further reading: http://events.linuxfoundation.org/sites/events/files/slides/Extending-Secure-Boot_0.pdf


## Tests

Functional black-box tests can be found in `tests/`, just run `test_all.sh` to launch all of them. Testing root shell functionality requires `get_root` to be built.

## More ideas

* keyboard logging
* hide process in netstat (used to work up to kernel 3.14)
* prevent hidden files from being modified
* prevent hidden files from being deleted (hook unlink)
* prevent hidden processes from being terminated (SIGTERM, SIGKILL)

## License

GPLv3
