"""Local, synthetic-only Step 9 end-to-end demonstration."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from ppml_healthcare.config import Settings, load_settings
from ppml_healthcare.crypto.factory import create_lrs_adapter
from ppml_healthcare.crypto.kem import CryptographyMLKEMAdapter
from ppml_healthcare.crypto.server_signatures import CryptographyMLDSAAdapter
from ppml_healthcare.errors import AdapterNotImplementedError
from ppml_healthcare.membership.registry import InMemoryMembershipRegistry
from ppml_healthcare.models.registry import InMemoryModelRegistry
from ppml_healthcare.protocol.client import HospitalRequestBuilder, InMemoryPendingRequestStore
from ppml_healthcare.protocol.rate_limit import InMemoryLinkabilityRateLimiter
from ppml_healthcare.protocol.replay import InMemoryReplayStore
from ppml_healthcare.protocol.response import HospitalResponseHandler, ServerResponseBuilder
from ppml_healthcare.protocol.server import RequestInferenceProcessor
from ppml_healthcare.protocol.validation import OrderedRequestValidator
from ppml_healthcare.schemas import ModelDescriptor, SyntheticFeatures


def run_demo(settings: Settings, *, output: TextIO | None = None) -> float:
    """Run a complete in-process request, inference, and response round trip."""
    stream = output or sys.stdout
    # Fail before creating state if the selected LRS backend is unavailable.
    lrs = create_lrs_adapter()
    print("MAYO-3 / RISC Zero LRS demo — research prototype; synthetic data only.", file=stream)
    hospital_public_key, hospital_secret_key = lrs.generate_keypair()
    decoy_public_key, _ = lrs.generate_keypair()
    membership = InMemoryMembershipRegistry(initial_members=(hospital_public_key, decoy_public_key))
    kem = CryptographyMLKEMAdapter()
    server_kem_keys = kem.generate_keypair()
    signer = CryptographyMLDSAAdapter()
    signing_keys = signer.generate_keypair()
    pending = InMemoryPendingRequestStore()
    models = InMemoryModelRegistry()

    request_id: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="ppml-healthcare-demo-") as temp_dir:
            artifact_path = Path(temp_dir) / "toy-risk-model.bin"
            artifact_path.write_bytes(b"synthetic demonstration model artifact v1\n")
            descriptor = ModelDescriptor(
                model_id="toy-risk",
                model_version="1.0",
                model_hash=hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            )
            models.register_model(descriptor, str(artifact_path))
            builder = HospitalRequestBuilder(
                protocol_version=settings.protocol_version,
                membership_epoch=membership.current_epoch(),
                hospital_secret_key=hospital_secret_key,
                model=descriptor,
                server_kem_public_key=server_kem_keys.public_key,
                lrs=lrs,
                pending_store=pending,
                settings=settings,
                kem=kem,
            )
            validator = OrderedRequestValidator(
                settings=settings,
                membership=membership,
                models=models,
                lrs=lrs,
                replay_store=InMemoryReplayStore(),
                rate_limiter=InMemoryLinkabilityRateLimiter(lrs),
            )
            processor = RequestInferenceProcessor(
                validator=validator,
                models=models,
                server_kem_private_key=server_kem_keys.private_key,
                kem=kem,
            )
            response_builder = ServerResponseBuilder(
                settings=settings,
                server_signing_private_key=signing_keys.private_key,
                signer=signer,
            )
            response_handler = HospitalResponseHandler(
                settings=settings,
                server_signing_public_key=signing_keys.public_key,
                pending_requests=pending,
                signer=signer,
            )

            request = builder.build_request(SyntheticFeatures(42, 120, 80, 24.5))
            request_id = request.request_id
            print("1. Built encrypted synthetic request.", file=stream)
            processed = processor.process_request(request)
            print("2. Validated request and ran toy inference.", file=stream)
            response = response_builder.create_response(request, processed)
            print("3. Encrypted and signed the response.", file=stream)
            prediction = response_handler.accept_response(response)
            print("4. Verified response and consumed pending client state.", file=stream)
            print(f"Synthetic toy prediction: {prediction}", file=stream)
            return float(prediction)
    finally:
        # Also clear client-side key material if any stage fails mid-run.
        if request_id is not None:
            pending.remove(request_id)
        print("Ephemeral keys and temporary model artifact discarded.", file=stream)


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Entry point for ``python -m ppml_healthcare.app`` and console script."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = argparse.ArgumentParser(description="Local synthetic PPML healthcare workflow demo")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the local request/response flow")
    parser.parse_args(argv)
    env = dict(os.environ if environ is None else environ)
    try:
        settings = load_settings(env)
        run_demo(settings, output=out)
    except (AdapterNotImplementedError, ValueError) as exc:
        print(f"Demo unavailable: {exc}", file=err)
        return 2
    except Exception as exc:
        # Keep diagnostics useful without printing request contents or key material.
        print(f"Demo failed: {type(exc).__name__}: {exc}", file=err)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
