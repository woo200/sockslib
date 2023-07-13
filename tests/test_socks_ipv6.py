"""
Unit tests for Sockslib IPv6

!!!! READ THIS !!!!

Reccomended to start a local TOR service when testing OR
a proxy that runs on port 9050.
"""

import sockslib
import unittest
import socket
import sys
import os

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)

sys.path.append(parentdir)


class TestSocksV6(unittest.TestCase):

    def setUp(self):
        self.socket = sockslib.SocksSocket(ip_version=socket.AF_INET6)
        self.socket.set_proxy(('::1', 9050),
                              sockslib.Socks.SOCKS5)
        self.socket.settimeout(10)

    def tearDown(self):
        self.socket.close()

    def test_socks5_direct(self):

        self.socket.connect(('2607:f8b0:4005:810::200e', 80)) # Googles IP addr, may be outdated soon
        self.socket.sendall(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

        self.socket.settimeout(10)  # Timeout so recv don't go on forevcer
        response = self.socket.recv(1024)

        self.assertNotEqual(response, b'')

    def test_socks4_ipv6_deny(self):
        self.socket.set_proxy(('127.0.0.1', 9050),
                              sockslib.Socks.SOCKS4)

        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('fdf7::', 80))


if __name__ == '__main__':
    unittest.main()
