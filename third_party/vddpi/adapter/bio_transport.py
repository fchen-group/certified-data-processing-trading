"""TLS transport for the measurement entry only, using real OpenSSL records.

Handshake and peer verification happen before request(); send() encrypts the
result into a MemoryBIO. flush() performs network writes after the measured
endpoint. The ordinary service continues to use its SSLSocket.
"""
import socket
import ssl


class DeferredTLS:
    def __init__(self, host, port, cert, key, ca):
        self.socket = socket.create_connection((host, port), timeout=30)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.load_verify_locations(cafile=ca)
        context.verify_mode = ssl.CERT_REQUIRED
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.records = bytearray()
        self.plaintext_bytes = 0
        for _ in range(100):
            try:
                self.tls.do_handshake()
                self._drain_handshake()
                break
            except ssl.SSLWantWriteError:
                self._drain_handshake()
            except ssl.SSLWantReadError:
                self._drain_handshake()
                block = self.socket.recv(65536)
                if not block:
                    raise RuntimeError("peer closed during TLS handshake")
                self.incoming.write(block)
        else:
            raise RuntimeError("TLS handshake did not converge")
        if not self.tls.getpeercert():
            raise RuntimeError("peer certificate missing")
        self.client_cn = dict(x[0] for x in self.tls.getpeercert()["subject"])["commonName"]

    def _drain_handshake(self):
        while self.outgoing.pending:
            self.socket.sendall(self.outgoing.read())

    def send(self, plaintext):
        if self.plaintext_bytes:
            raise RuntimeError("one successful result per measurement")
        offset = 0
        while offset < len(plaintext):
            # A renegotiation/request for peer input is a failed observation,
            # not an excuse to include network waiting in the measurement.
            n = self.tls.write(plaintext[offset:])
            if n <= 0:
                raise RuntimeError("TLS write made no progress")
            offset += n
        while self.outgoing.pending:
            self.records.extend(self.outgoing.read())
        if not self.records:
            raise RuntimeError("TLS produced no protected records")
        self.plaintext_bytes = offset
        return offset

    def flush(self):
        if not self.records:
            raise RuntimeError("no result to deliver")
        self.socket.sendall(self.records)
        # A clean TLS close is outside the measured result-protection interval.
        # Sending close_notify lets the verifier distinguish completion from a
        # truncated connection; no peer response is required for this harness.
        try:
            self.tls.unwrap()
        except ssl.SSLWantReadError:
            pass
        self._drain_handshake()

    def close(self):
        self.socket.close()
