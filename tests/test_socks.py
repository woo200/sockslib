"""
Unit tests for Sockslib

!!!! READ THIS !!!!

Reccomended to start a local TOR service when testing OR
a proxy that runs on port 9050.
"""

import sockslib
import unittest
import sys
import os

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)

sys.path.append(parentdir)


class TestSocks(unittest.TestCase):

    def setUp(self):
        self.socket = sockslib.SocksSocket()
        self.socket.set_proxy(('127.0.0.1', 9050),
                              sockslib.Socks.SOCKS5)
        self.socket.settimeout(10)

    def tearDown(self):
        self.socket.close()

    def test_socks5_direct(self):

        self.socket.connect(('1.1.1.1', 80))
        self.socket.sendall(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")

        self.socket.settimeout(10)  # Timeout so recv don't go on forevcer
        response = self.socket.recv(1024)

        self.assertNotEqual(response, b'')

    def test_socks5_domain(self):
        self.socket.connect(('myexternalip.com', 80))
        self.socket.sendall(b"GET /raw HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")

        self.socket.settimeout(10)  # Timeout so recv don't go on forevcer
        response = self.socket.recv(1024)

        self.assertNotEqual(response, b'')

    def test_socks5_udp(self):  # UDP is extremely hard to test because hardly any proxies support it
        pass

    def test_socks5_noauth(self):
        self.socket.auth = []
        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('1.1.1.1', 80))

    def test_socks5_invalid_ip(self):
        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('lol', 80))

    def test_socks5_general_error(self):
        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('0.0.0.0', 80))  # Should not be able to connect

    def test_socks4_direct(self):
        self.socket.set_proxy(('127.0.0.1', 9050),
                              sockslib.Socks.SOCKS4)

        self.socket.connect(('1.1.1.1', 80))
        self.socket.sendall(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n")

        self.socket.settimeout(10)  # Timeout so recv don't go on forevcer
        response = self.socket.recv(1024)

        self.assertNotEqual(response, b'')

    def test_socks4_general_error(self):
        self.socket.set_proxy(('127.0.0.1', 9050),
                              sockslib.Socks.SOCKS4)

        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('0.0.0.0', 80))  # Should not be able to connect

    def test_socks4_ipv6_deny(self):
        self.socket.set_proxy(('127.0.0.1', 9050),
                              sockslib.Socks.SOCKS4)

        with self.assertRaises(sockslib.SocksException):
            self.socket.connect(('fdf7::', 80))

    def test_socks_udp_fail(self):
        with self.assertRaises(sockslib.SocksException):
            self.socket.initudp()


if __name__ == '__main__':
    unittest.main()
