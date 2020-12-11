#!/usr/bin/env python

import sys
from scapy.all import sniff, get_if_list
from scapy.all import *

def handle_pkt(pkt):
    print("got a packet")
    # print(type(pkt))
    # print(pkt.summary())
    # pkt.show2()
    # pkt.show()
    print(hexdump(pkt))
    print(type(hexdump(pkt)))
    sys.stdout.flush()


def main():
    iface = 'eth0'
    print("listening on:", iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
