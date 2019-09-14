#!/usr/bin/env python

import argparse
import datetime as dt
import enum
import socket
import struct
from contextlib import suppress

from mbedtls import hashlib
from mbedtls.exceptions import TLSError
from mbedtls.pk import ECC, RSA
from mbedtls.tls import *
from mbedtls.tls import _enable_debug_output, _set_debug_level
from mbedtls.x509 import CRT, CSR, BasicConstraints

__all__ = ["Server"]


def make_root_cacert(now, *, pk, digestmod=hashlib.sha256):
    key = pk()
    key.generate()
    crt = CRT.selfsign(
        CSR.new(key, "CN=Trusted CA", digestmod()),
        key,
        not_before=now,
        not_after=now + dt.timedelta(days=90),
        serial_number=0x123456,
        basic_constraints=BasicConstraints(True, -1),
    )
    return crt, key


def chain(ca_crt, ca_key, now, *, pk, digestmod=hashlib.sha256):
    key = pk()
    key.generate()
    crt = ca_crt.sign(
        CSR.new(key, "CN=Intermediate CA", digestmod()),
        ca_key,
        not_before=now,
        not_after=now + dt.timedelta(days=90),
        serial_number=0x234567,
        basic_constraints=BasicConstraints(True, -1),
    )
    return crt, key


def _make_tls_connection(sock):
    assert sock
    conn, addr = sock.accept()
    return conn


def _make_dtls_connection(sock):
    assert sock
    conn, addr = sock.accept()
    conn.setcookieparam(addr[0].encode("ascii"))
    with suppress(HelloVerifyRequest):
        conn.do_handshake()

    _, (conn, addr) = conn, conn.accept()
    _.close()
    conn.setcookieparam(addr[0].encode("ascii"))
    return conn


class Server:
    def __init__(self, srv_conf, proto, address):
        super().__init__()
        self.srv_conf = srv_conf
        self.proto = proto
        self.address = address
        self._sock = None
        self._make_connection = {
            socket.SOCK_STREAM: _make_tls_connection,
            socket.SOCK_DGRAM: _make_dtls_connection,
        }[self.proto]

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()

    def __del__(self):
        self.stop()

    @property
    def context(self):
        if self._sock is None:
            return None
        return self._sock.context

    def start(self):
        if self._sock:
            self.stop()

        self._sock = ServerContext(self.srv_conf).wrap_socket(
            socket.socket(socket.AF_INET, self.proto)
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self.address)
        if self.proto is socket.SOCK_STREAM:
            self._sock.listen(1)

    def stop(self):
        if not self._sock:
            return

        self._sock.close()
        self._sock = None

    def run(self, conn_handler):
        if not self._sock:
            return

        with self:
            while True:
                self._run(conn_handler)

    def _run(self, conn_handler):
        with self._make_connection(self._sock) as conn:
            conn.do_handshake()
            conn_handler(conn)


class EchoHandler:
    def __init__(self, *, packet_size, end=b"\0"):
        self.packet_size = packet_size
        self.end = end

    def __call__(self, conn):
        while True:
            data = conn.recv(4096)
            if not data:
                break

            _ = conn.send(data)
            if data[-len(self.end) :] == self.end:
                break


def parse_args():
    parser = argparse.ArgumentParser(description="server")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--tls", dest="proto", action="store_const", const=socket.SOCK_STREAM
    )
    group.add_argument(
        "--dtls", dest="proto", action="store_const", const=socket.SOCK_DGRAM
    )
    parser.add_argument("--address", default="0.0.0.0")
    # or "127.0.0.1" if platform.system() == "Windows" else ""
    parser.add_argument("--port", default=4433, type=int)
    parser.add_argument("--debug", type=int)
    return parser.parse_args()


def main(args):
    now = dt.datetime.utcnow()
    ca0_crt, ca0_key = make_root_cacert(now, pk=RSA)
    ca1_crt, ca1_key = chain(ca0_crt, ca0_key, now, pk=ECC)
    ee0_crt, ee0_key = chain(ca1_crt, ca1_key, now, pk=ECC)

    with open("ca0.crt", "wt") as ca:
        ca.write(ca0_crt.to_PEM())

    trust_store = TrustStore()
    trust_store.add(CRT.from_DER(ca0_crt.to_DER()))

    conf = {
        socket.SOCK_STREAM: TLSConfiguration,
        socket.SOCK_DGRAM: DTLSConfiguration,
    }[args.proto](
        trust_store=trust_store,
        certificate_chain=([ee0_crt, ca1_crt], ee0_key),
        validate_certificates=False,
    )

    if args.debug is not None:
        _enable_debug_output(conf)
        _set_debug_level(args.debug)

    with Server(conf, args.proto, (args.address, args.port)) as srv:
        srv.run(EchoHandler(packet_size=4069))


if __name__ == "__main__":
    import faulthandler

    faulthandler.enable()
    with suppress(KeyboardInterrupt):
        main(parse_args())
