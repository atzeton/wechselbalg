#!/bin/sh

echo "after installation of the key, it should appear in the list below:"

sudo keyctl list %:.system_keyring
