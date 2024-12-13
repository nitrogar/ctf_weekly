from pwn import *


p = process("/usr/bin/julia chall.jl", shell=True)

p.recvuntil("5- Exit")

def send_c(s):
    p.sendline("1")
    p.recvuntil("5- Exit")
    return
def create_key():
    send_c("1")


def create_secret(s):
    send_c("2")
    p.recvuntil("Tell me your secret:")
    send_c(bytes(s))
send_c("4")
p.interactive()
