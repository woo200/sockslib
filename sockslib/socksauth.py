from sockslib.socks import AuthenticationMethod
import struct

class UserPassAuth(AuthenticationMethod):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def getId(self):
        return 0x02

    def for(self):
        return Socks.SOCKS5

    def authenticate(self, socket):
        socket.sendall(b"\x01" + struct.pack("B", len(self.username)) + self.username.encode() + struct.pack("B", len(self.password)) + self.password.encode())
        ver, status = socket.recv(2)

        return status == 0x00
