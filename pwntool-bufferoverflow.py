from pwn import *
import sys

io = process(sys.argv[1])
io.sendline(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
print(io.recv().decode())
