"""Step 9 CLI behavior with exactly one native LRS backend."""

from io import StringIO

import pytest

from ppml_healthcare.app import main, run_demo
from ppml_healthcare.config import Settings
from ppml_healthcare.errors import AdapterNotImplementedError


def test_demo_refuses_removed_mock_mode() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--insecure-test-mock"], environ={}, stdout=StringIO(), stderr=StringIO())
    assert exc.value.code == 2


def test_demo_fails_closed_without_native_lrs() -> None:
    output = StringIO()
    error = StringIO()
    result = main(["demo"], environ={}, stdout=output, stderr=error)
    assert result == 2
    assert "MAYO LRS backend is unavailable" in error.getvalue()
    assert output.getvalue() == ""


def test_run_demo_fails_closed_when_native_backend_missing() -> None:
    with pytest.raises(AdapterNotImplementedError, match="MAYO LRS backend is unavailable"):
        run_demo(Settings())
