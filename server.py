"""
Dev server for Hitster.

Serves over HTTPS with a self-signed cert so the browser grants camera access
(getUserMedia requires a secure context — plain HTTP only works on localhost,
not when accessing from another device on the LAN).

Usage:
    python3 server.py          # HTTPS on port 8443 (LAN-accessible)
    python3 server.py --http   # plain HTTP on port 8080 (localhost only)
"""

import argparse
import ipaddress
import socket
import ssl
import tempfile
import os
import http.server
import datetime

PORT_HTTPS = 8443
PORT_HTTP  = 8080


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def make_self_signed_cert():
    """Generate a temporary self-signed cert using only the stdlib."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import cryptography.x509.general_name as gn

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ip = local_ip()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "hitster-dev"),
        ])

        san_list = [x509.DNSName("localhost")]
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except Exception:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .sign(key, hashes.SHA256())
        )

        tmpdir = tempfile.mkdtemp()
        cert_path = os.path.join(tmpdir, "cert.pem")
        key_path  = os.path.join(tmpdir, "key.pem")

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))

        return cert_path, key_path, True

    except ImportError:
        return None, None, False


def serve_https(port):
    cert_path, key_path, ok = make_self_signed_cert()

    if not ok:
        print("  cryptography package not found — falling back to plain HTTP.")
        print("  Install it with:  pip3 install cryptography")
        print()
        serve_http(PORT_HTTP)
        return

    ip = local_ip()
    handler = http.server.SimpleHTTPRequestHandler

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    with http.server.HTTPServer(("0.0.0.0", port), handler) as httpd:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        print(f"\n  Hitster dev server running (HTTPS)\n")
        print(f"  Local:   https://localhost:{port}")
        print(f"  Network: https://{ip}:{port}")
        print()
        print("  ⚠  Your browser will show a certificate warning.")
        print("     Click 'Advanced' → 'Proceed' to continue.")
        print()
        print("  Press Ctrl+C to stop.\n")
        httpd.serve_forever()


def serve_http(port):
    ip = local_ip()
    handler = http.server.SimpleHTTPRequestHandler

    with http.server.HTTPServer(("0.0.0.0", port), handler) as httpd:
        print(f"\n  Hitster dev server running (HTTP)\n")
        print(f"  Local:   http://localhost:{port}")
        print(f"  Network: http://{ip}:{port}")
        print()
        print("  ⚠  Camera access only works on localhost (not from other devices)")
        print("     over plain HTTP. Use HTTPS mode to test on your phone.")
        print()
        print("  Press Ctrl+C to stop.\n")
        httpd.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hitster dev server")
    parser.add_argument("--http", action="store_true", help="Use plain HTTP (localhost only)")
    parser.add_argument("--port", type=int, help="Override port")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if args.http:
        serve_http(args.port or PORT_HTTP)
    else:
        serve_https(args.port or PORT_HTTPS)
