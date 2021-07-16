import socket
import struct
import regex
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
            match = regex.match(rident, ip)

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
        0x08: "Address type not supported"
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

    def authenticate(self, socket) -> bool:
        pass

class NoAuth(AuthenticationMethod):
    def getId(self):
        return 0x00

    def authenticate(self, socket):
        return True

class SocksSocket(socket.socket):
    def __init__(self):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy = None
        self.auth = [NoAuth()]

    def set_proxy(self, proxy, auth=[NoAuth()]):
        self.proxy = proxy
        self.auth = auth

    def __handshake(self, hp, auth=[NoAuth()]):
        if len(auth) < 1:
            raise SocksException("Must provide at least 1 authentication method. Leave the auth field blank for the default (No authentication)")

        self.sendall(b"\x05" + struct.pack("B", len(auth)) + bytes([method.getId() for method in auth]))
        ver, authc = self.recv(2)

        ip, port = hp

        # Check if authentication method is correct
        if authc == 0xFF:
            self.close()
            raise SocksException("No usable authentication methods available")

        for method in auth:
            if method.getId() == authc:
                if not method.authenticate(self):
                    self.close()
                    raise SocksException("Authentication Failed!")
                break

        # Send connect request packet
        addr_type = IpIdentify.identify(ip)
        if addr_type == None:
            raise SocksException(f"Invalid IP address or domain name: {ip}")

        self.sendall(b'\x05\x01\x00' + Socks5Address(ip, addr_type).getByteIp() + struct.pack("!H", port))

        ver, status, _ = self.recv(3)

        if status != 0x00:
            self.close()
            raise SocksException(f"Server denied connection request with response: {SocksErrors.request_denied(status)}")

        bndaddr = Socks5Address.readAddr(self)
        bndport, = struct.unpack("!H", self.recv(2))

        return bndaddr, bndport

    def connect(self, hp):
        if self.proxy == None:
            raise SocksException("No proxy selected")

        super().connect(self.proxy)
        self.__handshake(hp, self.auth)
