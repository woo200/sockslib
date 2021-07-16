

# Socks5Lib

Socks5lib is a library designed to make the usage of socks5 proxies as easy as possible.
This library can connect to proxies, authenticate, and then have the use of a normal python socket.

## Features
- IPv4 Support
- IPv6 Support
- Domain Support
- User/Pass authentication
- Easily customizable authentication
- Full socket api

## Examples
### Usage
This is an example usage that connects to a proxy at `127.0.0.1:9050` and then requests the page http://myexternalip.com/raw
```python
from sockslib import *

socket = SocksSocket()
socket.set_proxy(('127.0.0.1', 9050))
socket.connect(('myexternalip.com', 80))

socket.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n")

print(socket.recv(1024))
```
### Using other authentication methods
To use more authentication methods like User/Pass auth, you pass an array of authentication methods to the second parameter of `set_proxy`
```python
from sockslib import *

socket = SocksSocket()
socket.set_proxy(('127.0.0.1', 9050), [NoAuth(), UserPassAuth('username', 'password')])
socket.connect(('myexternalip.com', 80))

socket.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n")

print(socket.recv(1024))
```

### Implementing your own authentication methods
To implement your own socks5 authentication method, you must make a class that implements `sockslib.AuthenticationMethod` it requires that you implement a `getId()` function and an `authenticate(socket)` function. Note: the authenticate function must return a boolean, True if authentication succeeded and False if it failed.

```python
class UserPassAuth(AuthenticationMethod):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def getId(self):
        return 0x02  # 0x02 means Username / Password authentication, See https://en.wikipedia.org/wiki/SOCKS#SOCKS5 for a list of all authentication ID's

    def authenticate(self, socket):
        socket.sendall(b"\x01" + struct.pack("B", len(self.username)) + self.username.encode() + struct.pack("B", len(self.password)) + self.password.encode())
        ver, status = socket.recv(2)

        return status == 0x00
```

### Installation

`pip3 install sockslib`

### Issues

If you have any issues with this project please feel free to open a new issue on github
https://github.com/licyb200/sockslib/issues
