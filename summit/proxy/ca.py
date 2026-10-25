"""Certificate authority for TLS interception (optional feature).

Generating a CA and per-host leaf certificates is the one job the Python
standard library cannot do, so this module needs the optional
`cryptography` package (`pip install 'summit-scanner[proxy]'`). Everything
stays local: the CA key lives in ~/.summit/proxy-ca (or --ca-dir), leaves
are issued per host on demand and cached on disk next to it. Nothing is
sent anywhere - the CA exists so the proxy can present a certificate your
browser trusts after you trust the CA once, exactly like Burp's.
"""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

CA_CERT_NAME = "ca.crt"
CA_KEY_NAME = "ca.key"
LEAF_DAYS = 30


class CaUnavailable(RuntimeError):
    """Raised when TLS interception is requested without cryptography."""


def _require_cryptography():
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
    except ImportError as exc:
        raise CaUnavailable(
            "TLS interception needs the optional 'cryptography' package: "
            "pip install 'summit-scanner[proxy]'"
        ) from exc


def load_or_create_ca(ca_dir: Path) -> tuple[bytes, bytes]:
    """Return (cert_pem, key_pem) for the proxy CA, creating it on first use.

    The key is generated once and reused; deleting the directory rotates
    the CA (browsers will then need to trust the new certificate).
    """
    _require_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    ca_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = ca_dir / CA_CERT_NAME, ca_dir / CA_KEY_NAME
    if cert_path.exists() and key_path.exists():
        return cert_path.read_bytes(), key_path.read_bytes()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "summit proxy CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key_pem)
    try:
        key_path.chmod(0o600)  # best effort on platforms without POSIX perms
    except OSError:
        pass
    return cert_path.read_bytes(), key_path.read_bytes()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def issue_leaf(ca_dir: Path, host: str) -> Path:
    """Issue (or reuse) a leaf certificate for `host`, signed by the proxy CA.

    Returns the path of a PEM file holding the leaf plus the CA chain -
    exactly what ssl.SSLContext.load_cert_chain wants. Leaves are cached on
    disk so repeated visits to a host do not regenerate anything.
    """
    _require_cryptography()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    safe = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in host)
    leaf_path = ca_dir / f"leaf-{safe}.pem"
    if leaf_path.exists():
        return leaf_path

    ca_cert_pem, ca_key_pem = load_or_create_ca(ca_dir)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    san_names: list[x509.GeneralName] = []
    if _is_ip(host):
        san_names.append(x509.IPAddress(ipaddress.ip_address(host)))
    else:
        san_names.append(x509.DNSName(host))
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=LEAF_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    chain = cert.public_bytes(serialization.Encoding.PEM)
    chain += key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    chain += ca_cert_pem
    leaf_path.write_bytes(chain)
    return leaf_path
