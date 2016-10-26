#!/bin/sh

echo "generating signing key"
openssl req -new -x509 -newkey rsa:2048 -keyout wechselbalg.priv -outform DER -out wechselbalg.der -nodes -days 36500 -subj "/CN=wechselbalg rootkit/"
