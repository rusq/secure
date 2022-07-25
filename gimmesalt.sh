#!/bin/sh
dd if=/dev/urandom bs=256 count=1 | xxd -i
