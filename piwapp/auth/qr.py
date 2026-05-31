"""QR pairing string assembly and terminal rendering.

During companion registration WhatsApp sends one or more ``<ref>`` tokens. The
QR a phone scans encodes a comma-joined string of the current ref plus the
device's public keys and adv secret (all base64), exactly as Baileys builds it:

    ``ref,noiseKeyB64,signedIdentityKeyB64,advSecretB64``
"""

from __future__ import annotations

import base64


def build_qr_payload(
    ref: str,
    noise_public: bytes,
    signed_identity_public: bytes,
    adv_secret_key: bytes,
) -> str:
    """Assemble the comma-joined QR string a phone scans to link the device."""
    noise_b64 = base64.b64encode(noise_public).decode()
    identity_b64 = base64.b64encode(signed_identity_public).decode()
    adv_b64 = base64.b64encode(adv_secret_key).decode()
    return ",".join([ref, noise_b64, identity_b64, adv_b64])


def render_qr_terminal(payload: str) -> str:
    """Render ``payload`` as an ASCII QR code suitable for a terminal.

    Uses the ``qrcode`` library's ASCII renderer. Returns the string so callers
    can print it or route it elsewhere.
    """
    import io

    import qrcode

    qr = qrcode.QRCode(border=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(payload)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


def save_qr_png(payload: str, path: str) -> str:
    """Render ``payload`` as a PNG QR code at ``path`` (returns the path)."""
    import qrcode

    img = qrcode.make(payload, error_correction=qrcode.constants.ERROR_CORRECT_L)
    img.save(path)
    return path
