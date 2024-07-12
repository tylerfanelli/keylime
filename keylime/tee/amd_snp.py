# AMD SEV-SNP module for TEE boot attestation.

import base64
import uuid
import hashlib
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import pem, rfc2459

VALID_MEASUREMENTS = [
    b'eh5cJmwBCNvJu5T6kmlRMglAkV0Kr7QkZL2ItXnqFY0+Gg3DmyxgvZW5xIDNgYQf',
]

def snp_attest(report, vcek, uuid, n, e) -> bool:
    rd_verified = report_data_verify(report, uuid, n, e)
    if rd_verified is False:
        return False

    measurement = base64.b64encode(report[0x90:0xc0])
    if measurement not in VALID_MEASUREMENTS:
        return False

    if report_vcek_sign(report, vcek) is False:
        return False

    return True

def report_data_verify(report, uuid, n, e) -> bool:
    h = hashlib.sha512()
    h.update(uuid.bytes)
    h.update(n)
    h.update(e)
    h.update(report[0xe0:0x110])

    return h.digest() == report[0x50:0x90]

def report_vcek_sign(report, vcek) -> bool:
    measurable = report[:0x2a0]
    h = hashlib.sha384()
    h.update(measurable)

    sig = report[0x2a0:0x49f]
    key = vcek.public_key()

    return True
