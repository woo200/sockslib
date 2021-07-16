import socket
import struct
import re
import ipaddress

class SocksException(Exception):
    pass

class AddrTypes():
    IPv4 = b'\x01'
    IPv6 = b'\x04'
    Domain = b'\x03'

class Socks5Address():
    def __init__(self, ip, type=AddrTypes.IPv4):
        self.ip = ip
        self.type = type

    def getByteIp(self):
        if self.type == AddrTypes.IPv4:
            return AddrTypes.IPv4 + ipaddress.IPv4Address(self.ip).packed
        elif self.type == AddrTypes.IPv6:
            return AddrTypes.IPv6 + ipaddress.IPv6Address(self.ip).packed
        elif self.type == AddrTypes.Domain:
            return AddrTypes.Domain + bytes([len(self.ip)]) + self.ip.encode()
        else:
            raise TypeError(f"Unknown Address Type: {self.type}")

    def getIp(self):
        return self.ip

    def getType(self):
        return self.type

    @staticmethod
    def readAddr(sock):
        type = sock.recv(1)
        if type == AddrTypes.IPv4:
            return Socks5Address(ipaddress.IPv4Address(sock.recv(4)).exploded, AddrTypes.IPv4)
        elif type == AddrTypes.IPv6:
            return Socks5Address(ipaddress.IPv6Address(sock.recv(16)).compressed, AddrTypes.IPv6)
        elif type == AddrTypes.Domain:
            drlen, = sock.recv(1)
            return Socks5Address(sock.recv(drlen).decode(), AddrTypes.Domain)
        else:
            raise SocksException(f"Unknown address type: {type}")

    def __repr__(self):
        return self.getIp()

class IpIdentify():
    @staticmethod
    def identify(ip):
        try:
            addr = ipaddress.ip_address(ip)
            if isinstance(addr, ipaddress.IPv4Address):
                return AddrTypes.IPv4
            else:
                return AddrTypes.IPv6
        except:
            rident = r"^(?=.{1,255}$)(?!-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})*\.?(?<!-)$"
            match = re.match(rident, ip)

            if match:
                return AddrTypes.Domain
            return None

class SocksErrors():
    rqden = {
        0x00: "Granted",
        0x01: "General Faliure",
        0x02: "Connection not allowed by ruleset",
        0x03: "Network unreachable",
        0x04: "Host unreachable",
        0x05: "Connection refused by destination host",
        0x06: "TTL expired",
        0x07: "Command not supported / protocol error",
        0x08: "Address type not supported",
        0x5A: "Granted",
        0x5B: "Request rejected or failed",
        0x5C: "Request failed because client is not running identd (or not reachable from server)",
        0x5D: "Request failed because client's identd could not confirm the user ID in the request"
    }

    @staticmethod
    def request_denied(err):
        if err in SocksErrors.rqden:
            return f"({'0x%02x'%err}) {SocksErrors.rqden[err]}"
        else:
            return "Unknown Error"

class AuthenticationMethod():
    def getId(self) -> int:
        pass

    def for(self) -> int:
        pass

    def authenticate(self, socket) -> bool:
        pass

class NoAuth(AuthenticationMethod):
    def getId(self):
        return 0x00

    def for(self):
        return Socks.SOCKS5

    def authenticate(self, socket):
        return True

class Socks4Ident(AuthenticationMethod):
    def __init__(self, *args):
        if len(args) == 0:
            self.ident = ''
        else:
            self.ident = args[0]

    def for(self):
        return Socks.SOCKS4

    def getId(self):
        return 0x00

    def authenticate(self, socket):
        return True

class Socks:
    SOCKS5 = 5
    SOCKS4 = 4

class SocksSocket(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy = None
        self.auth = [NoAuth()]
        self.socktype = None

    def set_proxy(self, proxy, socktype=Socks.SOCKS5, auth=[NoAuth()]):
        self.proxy = proxy
        self.auth = auth
        self.socktype = socktype

    def __handshake_5(self, hp, auth=[NoAuth()]):
        if len(auth) < 1:
            self.close()
            raise SocksException("Must provide at least 1 authentication method. Leave the auth field blank for the default (No authentication)")

        self.sendall(b"\x05" + struct.pack("B", len(auth)) + bytes([method.getId() for method in auth]))
        ver, authc = self.recv(2)

        ip, port = hp

        # Check if authentication method is correct
        if authc == 0xFF:
            self.close()
            raise SocksException("No usable authentication methods available")

        for method in auth:
            if method.for() != Socks.SOCKS5:
                pass
            if method.getId() == authc:
                if not method.authenticate(self):
                    self.close()
                    raise SocksException("Authentication Failed!")
                break

        # Send connect request packet
        addr_type = IpIdentify.identify(ip)
        if addr_type == None:
            self.close()
            raise SocksException(f"Invalid IP address or domain name: {ip}")

        self.sendall(b'\x05\x01\x00' + Socks5Address(ip, addr_type).getByteIp() + struct.pack("!H", port))

        ver, status, _ = self.recv(3)

        if status != 0x00:
            self.close()
            raise SocksException(f"Server denied connection request with response: {SocksErrors.request_denied(status)}")

        bndaddr = Socks5Address.readAddr(self)
        bndport, = struct.unpack("!H", self.recv(2))

        return bndaddr, bndport

    def __handshake_4(self, hp, auth=[Socks4Ident("")]):
        ip, port = hp
        ident = IpIdentify.identify(ip)

        if ident == AddrTypes.Domain:
            ip = socket.gethostbyname_ex(ip)[2][0]
        elif ident == AddrTypes.IPv6:
            self.close()
            raise SocksException("IPv6 is not supported for Socks4")
        else:
            self.close()
            raise SocksException(f"Unknown IP type ({ip})")

        id = ""
        for method in auth:
            if isinstance(method, Socks4Ident):
                id = method.ident
                break

        self.sendall(b"\x04\x01" + struct.pack("!H", port) + ipaddress.IPv4Address(ip).packed + id.encode() + b"\x00")
        _, rep = self.recv(2)

        if rep != 0x5A:
            self.close()
            raise SocksException(f"Server denied connection request with response: {SocksErrors.request_denied(rep)}")

        dstport, = struct.unpack("!H", self.recv(2))
        dstip = ipaddress.IPv4Address(self.recv(4)).exploded

    def connect(self, hp):
        if self.proxy == None:
            raise SocksException("No proxy selected")

        super().connect(self.proxy)

        if self.socktype == Socks.SOCKS5:
            self.__handshake_5(hp, self.auth)
        elif self.socktype == Socks.SOCKS4:
            self.__handshake_4(hp, self.auth)
        else:
            raise SocksException(f"Unknown proxy type {self.socktype}")
