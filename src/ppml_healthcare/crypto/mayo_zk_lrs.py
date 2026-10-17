"""Project-owned Python boundary for the MAYO-3/RISC Zero LRS backend."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

from ppml_healthcare.crypto.lrs import LRSSignature


class MayoScopedZKLRSAdapter:
    """Invoke the native zero-knowledge backend using a strict JSON pipe.

    Membership rows and credentials are versioned opaque binary values made by
    the native backend. The credential contains a MAYO secret key and random
    link secret; only its enrolled row is public.
    """

    protocol_id = b"ppml-healthcare/msz-lrs/v1"

    def __init__(self, executable: str | os.PathLike[str] | None = None) -> None:
        configured = executable or os.environ.get("PPML_MSZ_LRS_EXECUTABLE")
        if configured:
            self._executable = Path(configured).expanduser().resolve()
        else:
            root = Path(__file__).resolve().parents[3]
            name = "ppml-msz-lrs.exe" if os.name == "nt" else "ppml-msz-lrs"
            self._executable = root / "native" / "msz_lrs" / "target" / "release" / name
        if not self._executable.is_file():
            raise FileNotFoundError(f"MAYO LRS executable not found: {self._executable}")

    def _call(self, request: dict[str, object]) -> dict[str, object]:
        env = os.environ.copy()
        env.pop("RISC0_DEV_MODE", None)
        try:
            result = subprocess.run(
                [str(self._executable)],
                input=json.dumps(request, separators=(",", ":")).encode("utf-8"),
                capture_output=True,
                check=False,
                timeout=900,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("MAYO LRS backend invocation failed") from exc
        if result.returncode != 0:
            # Native diagnostics are intentionally not echoed; they may contain
            # machine paths or backend details that should not enter API logs.
            raise RuntimeError("MAYO LRS backend rejected the operation")
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("MAYO LRS backend returned malformed output") from exc
        if not isinstance(value, dict):
            raise RuntimeError("MAYO LRS backend returned a non-object result")
        return value

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _unb64(value: object, field: str) -> bytes:
        if not isinstance(value, str):
            raise RuntimeError(f"native LRS result omitted {field}")
        try:
            return base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise RuntimeError(f"native LRS returned invalid {field}") from exc

    def generate_keypair(self) -> tuple[bytes, bytes]:
        result = self._call({"op": "keygen"})
        return self._unb64(result.get("public_key"), "public_key"), self._unb64(
            result.get("secret_key"), "secret_key"
        )

    @staticmethod
    def ring_digest(ring: tuple[bytes, ...], epoch: int) -> bytes:
        """Hash canonical MAYO membership rows exactly as the guest does."""
        if not isinstance(ring, tuple) or not 2 <= len(ring) <= 32:
            raise ValueError("anonymous MAYO ring must contain 2..32 rows")
        encoded_rows: list[bytes] = []
        previous: tuple[bytes, bytes] | None = None
        public_keys: set[bytes] = set()
        commitments: set[bytes] = set()
        for row in ring:
            if not isinstance(row, bytes) or len(row) < 44 or not row.startswith(b"MSZMEM01"):
                raise ValueError("invalid MAYO membership row")
            key_len = int.from_bytes(row[8:12], "big")
            if key_len == 0 or len(row) != 12 + key_len + 32:
                raise ValueError("invalid MAYO membership row length")
            public_key, commitment = row[12 : 12 + key_len], row[-32:]
            current = (public_key, commitment)
            if previous is not None and previous >= current:
                raise ValueError("MAYO ring rows are not in canonical order")
            if public_key in public_keys or commitment in commitments:
                raise ValueError("MAYO ring contains duplicate members or commitments")
            previous = current
            public_keys.add(public_key)
            commitments.add(commitment)
            encoded_rows.append(row[8:])
        payload = bytearray(b"MSZ-LRS/ring/v1")
        protocol = MayoScopedZKLRSAdapter.protocol_id
        payload.extend(len(protocol).to_bytes(4, "big"))
        payload.extend(protocol)
        payload.extend(epoch.to_bytes(8, "big"))
        payload.extend(len(ring).to_bytes(4, "big"))
        payload.extend(b"".join(encoded_rows))
        return hashlib.shake_256(payload).digest(32)

    def sign(
        self,
        secret_key: bytes,
        ring: tuple[bytes, ...],
        message: bytes,
        epoch: int,
        scope: bytes,
    ) -> LRSSignature:
        if (
            not isinstance(secret_key, bytes)
            or not isinstance(message, bytes)
            or not isinstance(scope, bytes)
        ):
            raise ValueError("credential, message, and scope must be bytes")
        result = self._call(
            {
                "op": "sign",
                "credential": self._b64(secret_key),
                "ring": [self._b64(row) for row in ring],
                "message": self._b64(message),
                "scope": self._b64(scope),
                "epoch": epoch,
            }
        )
        link_tag = self._unb64(result.get("link_tag"), "link_tag")
        if len(link_tag) != 32:
            raise RuntimeError("native LRS returned an invalid link tag")
        return LRSSignature(
            proof=self._unb64(result.get("proof"), "proof"),
            link_tag=link_tag,
            epoch=epoch,
            ring_digest=self.ring_digest(ring, epoch),
            scope=scope,
        )

    def verify(
        self,
        ring: tuple[bytes, ...],
        message: bytes,
        signature: LRSSignature,
        epoch: int,
        scope: bytes,
    ) -> bool:
        if (
            not isinstance(signature, LRSSignature)
            or not isinstance(signature.proof, bytes)
            or not isinstance(signature.link_tag, bytes)
            or len(signature.link_tag) != 32
        ):
            return False
        try:
            expected_ring_digest = self.ring_digest(ring, epoch)
        except (OverflowError, ValueError):
            return False
        if signature.ring_digest is not None and not hmac.compare_digest(
            signature.ring_digest, expected_ring_digest
        ):
            return False
        try:
            result = self._call(
                {
                    "op": "verify",
                    "proof": self._b64(signature.proof),
                    "ring": [self._b64(row) for row in ring],
                    "message": self._b64(message),
                    "scope": self._b64(scope),
                    "epoch": epoch,
                    "link_tag": self._b64(signature.link_tag),
                }
            )
            return result.get("valid") is True
        except (RuntimeError, ValueError, TypeError):
            return False

    def link(self, left: LRSSignature, right: LRSSignature) -> bool:
        if not isinstance(left, LRSSignature) or not isinstance(right, LRSSignature):
            return False
        if (
            not isinstance(left.link_tag, bytes)
            or not isinstance(right.link_tag, bytes)
            or len(left.link_tag) != 32
            or len(right.link_tag) != 32
            or left.epoch != right.epoch
            or left.ring_digest != right.ring_digest
            or left.scope != right.scope
        ):
            return False
        return hmac.compare_digest(left.link_tag, right.link_tag)
