from pymasque import WarpConnection

try:
  from asyncio_socks_server import Addon, Address, Connection, Server
except ImportError as e:
  raise ImportError("asyncio-socks-server is required for pymasque.socks. Run \"pip install 'pymasque[socks]'\" to install it.")

class WarpAddon(Addon):
  def __init__(self):
    self.warp = WarpConnection()

  async def on_connect(self, flow):
    stream = await self.warp.open_stream(flow.dst.host, flow.dst.port)
    await stream.ensure_response()
    return Connection(
      reader=stream,
      writer=stream,
      address=Address(flow.dst.host, flow.dst.port),
    )

  async def on_stop(self):
    await self.warp.close()

class WarpServer(Server):
  def __init__(self, **kwargs):
    addon = WarpAddon()
    super().__init__(addons=[addon], **kwargs)
    self.addon = addon

  def request_shutdown(self):
    try:
      self.addon.warp.close_all()
    except Exception:
      pass
    super().request_shutdown()

def serve(**kwargs):
  WarpServer(**kwargs).run()

def main(argv=None):
  import argparse

  parser = argparse.ArgumentParser(
    prog="pymasque.socks",
    description="SOCKS5 proxy routing through Cloudflare WARP/MASQUE",
  )
  parser.add_argument("--host", default="127.0.0.1", help="bind address")
  parser.add_argument("--port", type=int, default=1080, help="bind port")
  parser.add_argument("--auth", default=None, help="username:password")
  parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
  parser.add_argument("--log-format", default="text", choices=["text", "json"])
  args = parser.parse_args(argv)
  auth = None
  if args.auth:
    user, _, passwd = args.auth.partition(":")
    auth = (user, passwd)
  serve(host=args.host, port=args.port, auth=auth,
    log_level=args.log_level, log_format=args.log_format)


if __name__ == "__main__":
  main()
