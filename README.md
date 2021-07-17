




# SocksLib


Sockslib is a library designed to make the usage of socks proxies as easy as possible.
This library can connect to proxies, authenticate, and then have the use of a normal python socket.

![Downloads](https://pepy.tech/badge/sockslib)  [![PyPI version fury.io](https://badge.fury.io/py/sockslib.svg)](https://pypi.python.org/pypi/sockslib/)

## Features
- Socks5 support
- Socks4 support
- IPv4 Support
- IPv6 Support (Socks5)
- Domain Support
- User/Pass authentication  (Socks5)
- Easily customizable authentication (Socks5)
- Full socket api
## Documentation

#### Creating a new socket
```python
socket = sockslib.SocksSocket()
```
#### sock.set_proxy(proxy, type, authentication)
```python
socket.set_proxy (
	('127.0.0.1', 0),      # Ip, Port
	sockslib.Socks.SOCKS5, # SOCKS5/SOCKS4, (Optional)
	authentication         # Array of authentication methods (Optional)
)
```

## Examples
### Socks5
This is an example usage that connects to a Socks5 proxy at `127.0.0.1:9050` and then requests the page http://myexternalip.com/raw
```python
import sockslib

with sockslib.SocksSocket() as sock:
    sock.set_proxy(('127.0.0.1', 9050)) # Set proxy

    sock.connect(('myexternalip.com', 80)) # Connect to Server via proxy
    sock.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n") # Send HTTP Request
    print(sock.recv(1024)) # Print response
```
### Socks4
This is an example usage that connects to a Socks4 proxy at `127.0.0.1:9050` and then requests the page http://myexternalip.com/raw
```python
import sockslib

with sockslib.SocksSocket() as sock:
    sock.set_proxy(('127.0.0.1', 9050), sockslib.Socks.SOCKS4) # Set proxy

    sock.connect(('myexternalip.com', 80)) # Connect to Server via proxy
    sock.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n") # Send HTTP Request
    print(sock.recv(1024)) # Print response
```
#### Socks4 with identity authentication
```python
import sockslib

with sockslib.SocksSocket() as sock:
    auth_methods = [
        sockslib.Socks4Ident("ident")
    ]
    sock.set_proxy(('127.0.0.1', 9050), sockslib.Socks.SOCKS4, auth_methods) # Set proxy

    sock.connect(('myexternalip.com', 80)) # Connect to Server via proxy
    sock.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n") # Send HTTP Request
    print(sock.recv(1024)) # Print response
```

### Using other authentication methods (Socks5)
To use more authentication methods like User/Pass auth, you pass an array of authentication methods to the third parameter of `set_proxy` (Don't neglect to set the second parameter to the proxy type!)
```python
import sockslib

with sockslib.SocksSocket() as sock:
    auth_methods = [
        sockslib.NoAuth(),                             # No authentication
        sockslib.UserPassAuth('username', 'password'), # Username / Password authentication
    ]
    sock.set_proxy(('127.0.0.1', 9050), sockslib.Socks.SOCKS5, auth_methods) # Set proxy

    sock.connect(('myexternalip.com', 80)) # Connect to Server via proxy
    sock.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n") # Send HTTP Request
    print(sock.recv(1024)) # Print response
```

### Implementing your own authentication methods
To implement your own socks5 authentication method, you must make a class that implements `sockslib.AuthenticationMethod` it requires that you implement a `getId()` function, an `authenticate(socket)` function, and a `forP` function. Note: the authenticate function must return a boolean, True if authentication succeeded and False if it failed.

```python
from sockslib import AuthenticationMethod
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
```

### Installation

`pip3 install sockslib`

### Issues

If you have any issues with this project please feel free to open a new issue on github
https://github.com/licyb200/sockslib/issues
