#!/usr/bin/python3

# On D-Link/eCos system:
#
# flash read -f /var/dump -n devdata
# from WAN
# httpc -d 10.0.0.5:8000 -p TCP -i eth2 -f /var/dump
# or from LAN
# httpc -d 192.168.0.5:8000 -p TCP -i eth1 -f /var/dump

import socket
ADDR, PORT = ('0.0.0.0', 8000)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ADDR, PORT))
s.listen(1)
print("Listening on %s:%d..." % (ADDR,PORT))
count = 0
while True:
    conn, addr = s.accept()
    print(repr(addr))
    print("Connection from %s:%d" % addr)
    data = b''
    while True:
    	d = conn.recv(1024)
    	data += d
    	if not d:
    		break
    conn.sendall(b"""HTTP/1.1 200 OK
Connection: close
Content-Type: text/xml

<root></root>""")
    conn.close()
    print("Received %d bytes" % len(data))
    saved = False
    while not saved:
        fname = 'received%d.bin' % count
        try:
            with open(fname,'xb') as f:
                f.write(data)
                print("Writing to %s" % fname)
                saved = True
        except FileExistsError:
            count += 1
    count += 1
