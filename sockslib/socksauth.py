from sockslib.socks import AuthenticationMethod
from sockslib.socks import Socks
import struct

class UserPassAuth(AuthenticationMethod):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def getId(self):
        return 0x02 # 0x02 means password authentication, see https://en.wikipedia.org/wiki/SOCKS#SOCKS5 for more

    def forP(self):
        return Socks.SOCKS5 # For SOCKS5

    def authenticate(self, socket):
        socket.sendall(b"\x01" + struct.pack("B", len(self.username)) + self.username.encode() + struct.pack("B", len(self.password)) + self.password.encode()) # Send authentication packet
        ver, status = socket.recv(2) # Get authentication response

        return status == 0x00
