#!/bin/sh

sudo cat /boot/System.map-$(uname -r) | grep sys_call_table
