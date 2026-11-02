# pymasque

pymasque is a minimal implementation of a Cloudflare Warp MASQUE client in Python, powered by [qh3](https://github.com/jawah/qh3).

It only implements the [L4 mode of the MASQUE proxy](https://gist.github.com/ading2210/d146549760cac2e1e1b70db3b5805584). This is faster and does not require a userspace IP stack, but only supports TCP.

## Installation

Install it as a library:

```
pip3 install pymasque
```

Install it with a built-in SOCKS5 proxy:

```
pip3 install pymasque[socks]
```

## Usage

### SOCKS5 Proxy Mode

Use the SOCKS5 proxy mode to launch a SOCKS5 server that proxies all connections over Warp:
```
$ python3 -m pymasque.socks -h
usage: pymasque.socks [-h] [--host HOST] [--port PORT] [--auth AUTH] [--log-level {DEBUG,INFO,WARNING,ERROR}]
                      [--log-format {text,json}]

SOCKS5 proxy routing through Cloudflare WARP/MASQUE

options:
  -h, --help            show this help message and exit
  --host HOST           bind address
  --port PORT           bind port
  --auth AUTH           username:password
  --log-level {DEBUG,INFO,WARNING,ERROR}
  --log-format {text,json}
```

On first run, a new Cloudflare Warp account will be created, the details of which will be cached to the disk.

### As a Library

pymasque is easy to integrate into your asyncio applications.

### Basic Example:

```python
import asyncio
import pymasque

async def main():
  warp = pymasque.WarpConnection()
  stream = await warp.open_stream("cloudflare.com", 80)

  #send an http/1.1 payload
  payload = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: keepalive\r\n\r\n"
  await stream.send(payload.encode())
  response = await stream.recv()
  print(response.decode())

asyncio.run(main())
```

`pymasque.WarpConnection` and `pymasque.WarpStream` contain all that you need for sending TCP traffic over Cloudflare workers.

#### Creating New MASQUE Connections:

Creating a new `pymasque.WarpConnection` object and calling `.connect()` on it will create a new MASQUE connection to Cloudflare Warp. 

You don't need to explicitly call `.connect()`, it will automatically run when you create the first stream.

```python
warp = pymasque.WarpConnection()
await warp.connect()
```

#### Creating New Streams:

Streams can be created by calling `WarpConnection.open_stream(hostname, port)`. The hostname can be any domain name, IPv4 address, or IPv6 address. If a domain name is provided, it will be resolved locally using the system DNS resolver. This will return a `pymasque.WarpStream` object.

```python
warp = pymasque.WarpConnection()
stream = await warp.open_stream("example.com", 1234)
```

Once you have your stream object, you may call `stream.recv()` or `stream.send(data)` to recieve or send data. The data sent must be a bytes object.

```python
await stream.send(b"hello world")
response = await stream.recv()
```

## License

This project is licensed under the [GNU LGPL v3](https://www.gnu.org/licenses/lgpl-3.0.html).

> This license is mainly applied to libraries. You may copy, distribute and modify the software provided that modifications are described and licensed for free under LGPL. Derivatives works (including modifications or anything statically linked to the library) can only be redistributed under LGPL, but applications that use the library don't have to be.
> 
> \- From [tldrlegal.com](https://www.tldrlegal.com/license/gnu-lesser-general-public-license-v3-lgpl-3)