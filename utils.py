#!/usr/bin/env python
"""
utils.py

Created by 4Aiur on 2011-05-18.
"""

import socket
import struct


def check_ip(ipaddress):
    try:
        socket.inet_aton(ipaddress)
    except socket.error:
        # illegal ipaddress
        raise ValueError('Illegal ipaddress %s' % (ipaddress))
    return


class ConvertIP(object):

    def __init__(self):
        pass

    def ip2int(self, ip):
        return struct.unpack("!L", socket.inet_aton(ip))[0]

    def int2ip(self, i):
        return socket.inet_ntoa(struct.pack("!L", i))

    def ip2hex(self, ip):
        check_ip(ip)
        ip_int = struct.unpack("!L", socket.inet_aton(ip))[0]
        #ip_hex = hex(ip_int)
        ip_hex = '%08x' % (ip_int)
        return ip_hex

    def hex2ip(self, ip_hex):
        ip_int = int(ip_hex, 16)
        ip = socket.inet_ntoa(struct.pack('!L', ip_int))
        return ip

if __name__ == '__main__':
    #ipaddress = '1.2.3.255'
    #ip_int = 16909311
    #ip_hex = 0x10203ff
    convert_ip = ConvertIP()
    ipaddress = '1.2.3.255'
    ip_hex = convert_ip.ip2hex(ipaddress)
    print('ip2hex: %s -> %s' % (ipaddress, ip_hex))
    ip_hex = '0x10203ff'
    ipaddress = convert_ip.hex2ip(ip_hex)
    print('hex2ip: %s -> %s' % (ip_hex, ipaddress))

    ipaddress = '205.185.117.238'
    ip_hex = convert_ip.ip2hex(ipaddress)
    print('ip2hex: %s -> %s' % (ipaddress, ip_hex))

