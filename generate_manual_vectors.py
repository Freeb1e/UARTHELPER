#!/usr/bin/env python3
"""Generate line-aligned UART commands and reference outputs for manual tests."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Iterable


UARTHELPER_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = UARTHELPER_ROOT.parent
SCLOUD_PARAMETERS = (128, 192, 256, 512)
MLKEM_PARAMETERS = (512, 768, 1024)
MLDSA_PARAMETERS = (44, 65, 87)


class ManualVectorError(RuntimeError):
    """Raised when generated data does not match the checked-in vector set."""


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ManualVectorError(f"cannot load Python module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_generators() -> dict[str, ModuleType]:
    modules: dict[str, ModuleType] = {}

    # The Scloud stage scripts intentionally share their parser through these
    # two historical module names. Bind them in dependency order.
    modules["scloud_keygen"] = load_module(
        "manual_scloud_keygen", UARTHELPER_ROOT / "SCLOUDKEYGEN/run_keygen_tests.py"
    )
    sys.modules["run_keygen_tests"] = modules["scloud_keygen"]
    modules["scloud_encaps"] = load_module(
        "manual_scloud_encaps", UARTHELPER_ROOT / "SCLOUDENCAPS/run_encaps_tests.py"
    )
    sys.modules["run_encaps_tests"] = modules["scloud_encaps"]
    modules["scloud_decaps"] = load_module(
        "manual_scloud_decaps", UARTHELPER_ROOT / "SCLOUDDECAPS/run_decaps_tests.py"
    )

    for name, directory, script in (
        ("mlkem_keygen", "MLKEMKEYGEN", "run_keygen_tests.py"),
        ("mlkem_encaps", "MLKEMENCAPS", "run_encaps_tests.py"),
        ("mlkem_decaps", "MLKEMDECAPS", "run_decaps_tests.py"),
        ("mldsa_keygen", "MLDSAKEYGEN", "run_keygen_tests.py"),
        ("mldsa_sign", "MLDSASIGN", "run_sign_tests.py"),
        ("mldsa_verify", "MLDSAVERIFY", "run_verify_tests.py"),
    ):
        modules[name] = load_module(
            f"manual_{name}", UARTHELPER_ROOT / directory / script
        )
    return modules


def lines(values: Iterable[str]) -> bytes:
    return "".join(f"{value}\n" for value in values).encode("ascii")


def hex_lines(values: Iterable[bytes]) -> bytes:
    return lines(value.hex().upper() for value in values)


def command_bytes(commands: Iterable[bytes]) -> bytes:
    result = b"".join(commands)
    if result and not result.endswith(b"\n"):
        raise ManualVectorError("generated command stream is not newline terminated")
    return result


def require_count(label: str, values: list[object], expected: int) -> None:
    if len(values) != expected:
        raise ManualVectorError(
            f"{label}: generated {len(values)} cases, expected {expected}"
        )


def scloud_artifacts(
    modules: dict[str, ModuleType],
) -> tuple[dict[Path, bytes], dict[Path, bytes]]:
    generated: dict[Path, bytes] = {}
    protected: dict[Path, bytes] = {}
    vector_root = PROJECT_ROOT / "third_party/Scloud+/Test_Vectors"

    for parameter in SCLOUD_PARAMETERS:
        vector_path = (
            vector_root / f"KAT_KEM_Scloudplus-{parameter}-SM3-packed10.txt"
        )

        keygen = modules["scloud_keygen"]
        loaded_parameter, key_vectors = keygen.load_vectors(vector_path)
        if loaded_parameter != parameter:
            raise ManualVectorError(f"Scloud+ KeyGen parameter mismatch: {vector_path}")
        require_count(f"Scloud+{parameter} KeyGen", key_vectors, 10)
        key_commands = command_bytes(keygen.build_commands(parameter, key_vectors))
        key_dir = UARTHELPER_ROOT / "SCLOUDKEYGEN"
        protected[key_dir / f"keygen_commands_{parameter}.txt"] = key_commands
        generated[key_dir / f"pk_ref_{parameter}.txt"] = hex_lines(
            vector.public_key for vector in key_vectors
        )
        generated[key_dir / f"sk_ref_{parameter}.txt"] = hex_lines(
            vector.secret_key for vector in key_vectors
        )

        encaps = modules["scloud_encaps"]
        loaded_parameter, encaps_vectors = encaps.load_kats(vector_path)
        if loaded_parameter != parameter:
            raise ManualVectorError(f"Scloud+ Encaps parameter mismatch: {vector_path}")
        require_count(f"Scloud+{parameter} Encaps", encaps_vectors, 10)
        encaps_commands = command_bytes(
            encaps.build_commands(parameter, encaps_vectors)
        )
        encaps_dir = UARTHELPER_ROOT / "SCLOUDENCAPS"
        protected[encaps_dir / f"encaps_commands_{parameter}.txt"] = encaps_commands
        generated[encaps_dir / f"ct_ref_{parameter}.txt"] = hex_lines(
            vector.ct for vector in encaps_vectors
        )
        generated[encaps_dir / f"ss_ref_{parameter}.txt"] = hex_lines(
            vector.ss for vector in encaps_vectors
        )

        decaps = modules["scloud_decaps"]
        loaded_parameter, decaps_cases = decaps.load_cases(vector_path)
        if loaded_parameter != parameter:
            raise ManualVectorError(f"Scloud+ Decaps parameter mismatch: {vector_path}")
        require_count(f"Scloud+{parameter} Decaps", decaps_cases, 11)
        decaps_commands = command_bytes(
            decaps.build_commands(parameter, decaps_cases)
        )
        decaps_dir = UARTHELPER_ROOT / "SCLOUDDECAPS"
        protected[decaps_dir / f"decaps_commands_{parameter}.txt"] = decaps_commands
        generated[decaps_dir / f"ss_ref_{parameter}.txt"] = hex_lines(
            case.ss for case in decaps_cases
        )
        generated[decaps_dir / f"fail_mask_ref_{parameter}.txt"] = lines(
            str(case.fail_mask) for case in decaps_cases
        )

    return generated, protected


def mlkem_artifacts(modules: dict[str, ModuleType]) -> dict[Path, bytes]:
    generated: dict[Path, bytes] = {}

    for parameter in MLKEM_PARAMETERS:
        keygen = modules["mlkem_keygen"]
        key_dir = UARTHELPER_ROOT / "MLKEMKEYGEN"
        key_path = key_dir / f"keygen_commands_{parameter}.txt"
        coins = keygen.load_coins(key_path, parameter)
        require_count(f"ML-KEM-{parameter} KeyGen", coins, 3)
        key_vectors = keygen.build_golden(parameter, coins)
        generated[key_path] = lines(
            f"KEYGEN {parameter} {value.hex().upper()}" for value in coins
        )
        generated[key_dir / f"pk_ref_{parameter}.txt"] = hex_lines(
            vector.public_key for vector in key_vectors
        )
        generated[key_dir / f"sk_ref_{parameter}.txt"] = hex_lines(
            vector.secret_key for vector in key_vectors
        )

        encaps = modules["mlkem_encaps"]
        encaps_dir = UARTHELPER_ROOT / "MLKEMENCAPS"
        encaps_inputs = encaps.load_inputs(
            encaps_dir / f"encaps_inputs_{parameter}.txt", parameter
        )
        require_count(f"ML-KEM-{parameter} Encaps", encaps_inputs, 3)
        encaps_vectors = encaps.build_golden(parameter, encaps_inputs)
        generated[encaps_dir / f"encaps_commands_{parameter}.txt"] = lines(
            f"ENCAPS {parameter} {vector.public_key.hex().upper()} "
            f"{vector.encaps_coins.hex().upper()}"
            for vector in encaps_vectors
        )
        generated[encaps_dir / f"ct_ref_{parameter}.txt"] = hex_lines(
            vector.ciphertext for vector in encaps_vectors
        )
        generated[encaps_dir / f"ss_ref_{parameter}.txt"] = hex_lines(
            vector.shared_secret for vector in encaps_vectors
        )

        decaps = modules["mlkem_decaps"]
        decaps_dir = UARTHELPER_ROOT / "MLKEMDECAPS"
        decaps_inputs = decaps.load_inputs(
            decaps_dir / f"decaps_inputs_{parameter}.txt", parameter
        )
        require_count(f"ML-KEM-{parameter} Decaps sources", decaps_inputs, 3)
        decaps_vectors = decaps.build_golden(parameter, decaps_inputs)
        require_count(f"ML-KEM-{parameter} Decaps", decaps_vectors, 6)
        generated[decaps_dir / f"decaps_commands_{parameter}.txt"] = lines(
            f"DECAPS {parameter} {vector.secret_key.hex().upper()} "
            f"{vector.ciphertext.hex().upper()}"
            for vector in decaps_vectors
        )
        generated[decaps_dir / f"ss_ref_{parameter}.txt"] = hex_lines(
            vector.shared_secret for vector in decaps_vectors
        )

    return generated


def mldsa_artifacts(modules: dict[str, ModuleType]) -> dict[Path, bytes]:
    generated: dict[Path, bytes] = {}

    for parameter in MLDSA_PARAMETERS:
        keygen = modules["mldsa_keygen"]
        key_dir = UARTHELPER_ROOT / "MLDSAKEYGEN"
        key_path = key_dir / f"keygen_commands_{parameter}.txt"
        seeds = keygen.load_seeds(key_path, parameter)
        require_count(f"ML-DSA-{parameter} KeyGen", seeds, 3)
        key_vectors = keygen.build_golden(parameter, seeds)
        generated[key_path] = lines(
            f"KEYGEN {parameter} {seed.hex().upper()}" for seed in seeds
        )
        generated[key_dir / f"pk_ref_{parameter}.txt"] = hex_lines(
            vector.public_key for vector in key_vectors
        )
        generated[key_dir / f"sk_ref_{parameter}.txt"] = hex_lines(
            vector.secret_key for vector in key_vectors
        )

        sign = modules["mldsa_sign"]
        sign_dir = UARTHELPER_ROOT / "MLDSASIGN"
        sign_inputs = sign.load_inputs(
            sign_dir / f"sign_commands_{parameter}.txt", parameter
        )
        require_count(f"ML-DSA-{parameter} Sign", sign_inputs, 3)
        sign_vectors = sign.build_golden(parameter, sign_inputs)
        generated[sign_dir / f"sign_uart_commands_{parameter}.txt"] = lines(
            f"SIGN {parameter} {vector.secret_key.hex().upper()} "
            f"{vector.source.message.hex().upper()} "
            f"{vector.source.sign_random.hex().upper()}"
            for vector in sign_vectors
        )
        generated[sign_dir / f"sig_ref_{parameter}.txt"] = hex_lines(
            vector.signature for vector in sign_vectors
        )

        verify = modules["mldsa_verify"]
        verify_dir = UARTHELPER_ROOT / "MLDSAVERIFY"
        verify_inputs = verify.load_inputs(
            verify_dir / f"verify_commands_{parameter}.txt", parameter
        )
        require_count(f"ML-DSA-{parameter} Verify sources", verify_inputs, 3)
        verify_vectors = verify.build_golden(parameter, verify_inputs)
        require_count(f"ML-DSA-{parameter} Verify", verify_vectors, 6)
        generated[verify_dir / f"verify_uart_commands_{parameter}.txt"] = lines(
            f"VERIFY {parameter} {vector.public_key.hex().upper()} "
            f"{vector.message.hex().upper()} {vector.signature.hex().upper()}"
            for vector in verify_vectors
        )
        generated[verify_dir / f"valid_ref_{parameter}.txt"] = lines(
            str(int(vector.expected_valid)) for vector in verify_vectors
        )

    return generated


def compare(path: Path, expected: bytes) -> None:
    try:
        actual = path.read_bytes()
    except OSError as error:
        raise ManualVectorError(f"cannot read {path.relative_to(PROJECT_ROOT)}: {error}") from error
    if actual == expected:
        return
    actual_lines = actual.splitlines()
    expected_lines = expected.splitlines()
    limit = min(len(actual_lines), len(expected_lines))
    differing = next(
        (index + 1 for index in range(limit) if actual_lines[index] != expected_lines[index]),
        limit + 1,
    )
    raise ManualVectorError(
        f"{path.relative_to(PROJECT_ROOT)} differs at line {differing} "
        f"(actual {len(actual_lines)} lines, expected {len(expected_lines)} lines)"
    )


def write_or_check(artifacts: dict[Path, bytes], check: bool) -> None:
    action = "Checked" if check else "Wrote"
    for path, content in sorted(artifacts.items()):
        if check:
            compare(path, content)
        else:
            path.write_bytes(content)
        print(f"{action} {path.relative_to(PROJECT_ROOT)} ({len(content.splitlines())} lines)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="recompute all outputs and fail instead of modifying stale files",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        modules = load_generators()
        generated, protected = scloud_artifacts(modules)
        generated.update(mlkem_artifacts(modules))
        generated.update(mldsa_artifacts(modules))

        # Existing Scloud command streams are canonical KAT data. Never rewrite
        # them from this aggregate tool; fail if their derivation has changed.
        write_or_check(protected, True)
        write_or_check(generated, args.check)
        print(f"PASS: {len(protected)} command files and {len(generated)} artifacts are consistent")
        return 0
    except (ManualVectorError, OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
