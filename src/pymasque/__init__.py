import os
import base64
import logging
import re
import json
import ssl
import asyncio
from datetime import datetime, timezone, timedelta

import platformdirs
import niquests
import qh3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_public_key

#a client for the cloudflare warp l4 proxy service
#based on https://github.com/Diniboy1123/usque

cf_api = "https://api.cloudflareclient.com/v0a4471"
cf_headers = {
  "User-Agent": "WARP for Android",
  "CF-Client-Version": "a-6.35-4471"
}
cf_sni = "consumer-masque-proxy.cloudflareclient.com"

dirs = platformdirs.PlatformDirs("pymasque")
data_dir = dirs.user_data_path
registration_file = data_dir / "warp_config.json"

async def register():
  reg_key = base64.b64encode(os.urandom(32)).decode()
  tos_date = datetime.now().astimezone().isoformat(timespec="milliseconds")

  reg_response = await niquests.apost(cf_api + "/reg", json={
    "key": reg_key,
    "install_id": "",
    "fcm_token": "",
    "tos": tos_date,
    "model": "PC",
    "serial_number": os.urandom(4).hex(),
    "os_version": "",
    "key_type": "curve25519",
    "tunnel_type": "wireguard",
    "locale": "en_US"
  }, headers=cf_headers)
  reg_response.raise_for_status()
  registration = reg_response.json()

  device_id = registration["id"]
  token = registration["token"]
  private_key = ec.generate_private_key(ec.SECP256R1())
  private_key_der = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
  private_key_str = base64.b64encode(private_key_der).decode()
  public_key_der = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
  public_key_str = base64.b64encode(public_key_der).decode()

  enroll_response = await niquests.apatch(cf_api + f"/reg/{device_id}", json={
    "key": public_key_str,
    "key_type": "secp256r1",
    "tunnel_type": "masque",
    "name": ""
  }, headers={**cf_headers, "Authorization": f"Bearer {token}"})
  enroll_response.raise_for_status()
  enrollment = enroll_response.json()

  peer = enrollment["config"]["peers"][0]
  endpoint_ipv4 = peer["endpoint"]["v4"].split(":")[0]
  endpoint_ipv6 = re.findall(r"\[(.+)\]:0", peer["endpoint"]["v6"])[0]

  warp_config = {
    "id": device_id,
    "token": token,
    "private_key": private_key_str,
    "endpoint_ipv4": endpoint_ipv4,
    "endpoint_ipv6": endpoint_ipv6,
    "endpoint_public_key": peer["public_key"]
  }
  return warp_config

async def read_registration():
  if registration_file.exists():
    return json.loads(registration_file.read_text())
  else:
    logging.info("creating new cf warp registration")
    registration = await register()
    data_dir.mkdir(exist_ok=True, parents=True)
    registration_file.write_text(json.dumps(registration, indent=2))
    logging.info(f"saved cf warp registration data to {registration_file}")
    return registration

class _WarpQuicProtocol(qh3.asyncio.QuicConnectionProtocol):
  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.h3 = qh3.H3Connection(self._quic)
    self.streams = {}

  @property
  def closed(self):
    return self._closed.is_set()

  @property
  def peercert(self):
    return self._quic.get_peercert()

  def open_h3_stream_id(self):
    return self._quic.get_next_available_stream_id(is_unidirectional=False)

  def reset_h3_stream(self, stream_id):
    try:
      self._quic.reset_stream(stream_id, 0)
      self.transmit()
    except Exception:
      pass

  def quic_event_received(self, event):
    super().quic_event_received(event)
    for h3_event in self.h3.handle_event(event):
      stream = self.streams.get(h3_event.stream_id)
      if stream is not None:
        stream.on_h3_event(h3_event)

class WarpStream:
  def __init__(self, proto, stream_id, timeout=15):
    self._proto = proto
    self._id = stream_id
    self._timeout = timeout
    self._headers = asyncio.get_running_loop().create_future()
    self._incoming = asyncio.Queue()
    self._ready = False
    self._eof = False
    proto.streams[stream_id] = self

  def on_h3_event(self, hev):
    if isinstance(hev, qh3.h3_events.HeadersReceived):
      if not self._headers.done():
        self._headers.set_result((hev.headers, hev.stream_ended))
      if hev.stream_ended:
        self._incoming.put_nowait((b"", True))
    elif isinstance(hev, qh3.h3_events.DataReceived):
      self._incoming.put_nowait((hev.data, hev.stream_ended))
    elif isinstance(hev, (qh3.h3_events.StreamReset, qh3.h3_events.StopSending)):
      self._incoming.put_nowait((None, True))
      if not self._headers.done():
        self._headers.set_exception(ConnectionResetError(f"stream {self._id} reset"))

  async def ensure_response(self):
    if self._ready:
      return
    try:
      async with asyncio.timeout(self._timeout):
        headers, _ = await self._headers
    except TimeoutError:
      raise ConnectionError("CONNECT timed out")
    status = dict(headers).get(b":status", b"").decode()
    if not status.startswith("2"):
      raise ConnectionError(f"CONNECT rejected with status {status}")
    self._ready = True

  async def recv(self):
    await self.ensure_response()
    if self._eof:
      return b""
    data, ended = await self._incoming.get()
    if data is None or ended:
      self._eof = True
      return bytes(data or b"")
    return bytes(data)

  async def send(self, data):
    try:
      self._proto.h3.send_data(self._id, data, False)
      self._proto.transmit()
    except (ValueError, RuntimeError) as e:
      raise ConnectionResetError(f"stream {self._id} closed") from e

  def write_eof(self):
    self._proto.h3.send_data(self._id, b"", True)
    self._proto.transmit()

  def close(self):
    self._proto.reset_h3_stream(self._id)
    self._proto.streams.pop(self._id, None)
    if not self._headers.done():
      self._headers.cancel()

class WarpConnection:
  def __init__(self):
    self.quic_context = None
    self.quic_protocol = None

  async def connect(self):
    if self.quic_protocol is not None and not self.quic_protocol.closed:
      return self.quic_protocol
    registration = await read_registration()

    private_key_der = base64.b64decode(registration["private_key"])
    private_key = load_der_private_key(private_key_der, password=None)
    pkcs8_der = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    quic_private_key = qh3._hazmat.EcPrivateKey(pkcs8_der, 256, True)

    now = datetime.now(timezone.utc)
    cert_der = (
      x509.CertificateBuilder()
      .serial_number(1)
      .issuer_name(x509.Name([]))
      .subject_name(x509.Name([]))
      .public_key(private_key.public_key())
      .not_valid_before(now)
      .not_valid_after(now + timedelta(hours=24))
      .sign(private_key, hashes.SHA256())
      .public_bytes(serialization.Encoding.DER)
    )
    quic_cert = qh3._hazmat.Certificate(cert_der)

    quic_config = qh3.QuicConfiguration(
      is_client=True, alpn_protocols=["h3"], server_name=cf_sni,
      certificate=quic_cert, private_key=quic_private_key,
      verify_mode=ssl.CERT_NONE, verify_hostname=False,
      offer_ec_key_shares=True,
    )
    
    logging.info("connecting to cloudflare warp server")
    self.quic_context = qh3.asyncio.connect(registration["endpoint_ipv4"], 443, configuration=quic_config, create_protocol=_WarpQuicProtocol)
    self.quic_protocol = await self.quic_context.__aenter__()

    peer_public_key = self.quic_protocol.peercert.public_key()
    edge_key = load_pem_public_key(registration["endpoint_public_key"].encode())
    edge_public_key = edge_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if peer_public_key != edge_public_key:
      await self.close()
      raise ssl.SSLCertVerificationError("edge public key does not match")
    asyncio.create_task(self.keepalive())
    return self.quic_protocol
  
  async def close(self):
    if self.quic_context is not None:
      await self.quic_context.__aexit__(None, None, None)
    self.quic_context = None
    self.quic_protocol = None

  async def open_stream(self, target, timeout=15):
    proto = await self.connect()
    s = WarpStream(proto, proto.open_h3_stream_id(), timeout)
    proto.h3.send_headers(s._id, [
      (b":method", b"CONNECT"),
      (b":authority", target.encode()),
      (b"host", target.encode()),
    ], end_stream=False)
    proto.transmit()
    return s
  
  async def keepalive(self):
    while self.quic_protocol:
      await asyncio.sleep(15)
      try:
        await self.quic_protocol.ping()
      except Exception:
        continue
  
async def test_main():
  logging.basicConfig(
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    level=logging.DEBUG,
    datefmt="%Y/%m/%d - %H:%M:%S"
  )
  await read_registration()
  conn = WarpConnection()
  await conn.connect()
  await conn.quic_protocol.wait_closed()
  await conn.close()