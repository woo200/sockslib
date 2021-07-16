import sockslib

socket = sockslib.SocksSocket()
socket.set_proxy(('127.0.0.1', 9050), [sockslib.NoAuth(), sockslib.UserPassAuth('username', 'password')])
socket.connect(('myexternalip.com', 80))

socket.sendall(b"GET /raw HTTP/1.1\r\nHost: myexternalip.com\r\n\r\n")

print(socket.recv(1024))
