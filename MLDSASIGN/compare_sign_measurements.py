#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class ComparisonError(RuntimeError):
    pass


@dataclass(frozen=True)
class Measurement:
    parameter: int
    implementation: str
    case_number: int
    input_id: str
    signature_sha256: str
    algorithm_cycles: int
    attempts: int


def load_measurements(path: Path, expected_implementation: str) -> list[Measurement]:
    required = {
        "format_version", "parameter", "implementation", "case_number",
        "input_id", "keygen_seed", "message", "sign_random",
        "signature_sha256", "algorithm_cycles", "attempts",
    }
    try:
        with path.open(newline="", encoding="ascii") as source:
            reader = csv.DictReader(source)
            missing = required - set(reader.fieldnames or ())
            if missing:
                raise ComparisonError(
                    f"{path} is missing columns: {', '.join(sorted(missing))}"
                )
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as error:
        raise ComparisonError(f"cannot read {path}: {error}") from error
    if not rows:
        raise ComparisonError(f"{path} contains no measurements")

    measurements: list[Measurement] = []
    seen: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        try:
            if row["format_version"] != "1":
                raise ComparisonError(
                    f"{path}:{row_number}: unsupported format version"
                )
            if row["implementation"] != expected_implementation:
                raise ComparisonError(
                    f"{path}:{row_number}: expected {expected_implementation}, "
                    f"found {row['implementation']}"
                )
            parameter = int(row["parameter"])
            case_number = int(row["case_number"])
            cycles = int(row["algorithm_cycles"])
            attempts = int(row["attempts"])
            inputs = [
                bytes.fromhex(row[name])
                for name in ("keygen_seed", "message", "sign_random")
            ]
        except (ValueError, TypeError) as error:
            raise ComparisonError(
                f"{path}:{row_number}: malformed numeric or hexadecimal field"
            ) from error
        if parameter not in (44, 65, 87) or case_number < 1:
            raise ComparisonError(f"{path}:{row_number}: invalid case metadata")
        if cycles <= 0 or attempts < 1 or any(len(value) != 32 for value in inputs):
            raise ComparisonError(f"{path}:{row_number}: invalid measurement value")
        expected_id = hashlib.sha256(
            parameter.to_bytes(2, "big") + b"".join(inputs)
        ).hexdigest()
        if row["input_id"] != expected_id:
            raise ComparisonError(f"{path}:{row_number}: input_id does not match inputs")
        try:
            signature_hash = bytes.fromhex(row["signature_sha256"])
        except ValueError as error:
            raise ComparisonError(
                f"{path}:{row_number}: malformed signature hash"
            ) from error
        if len(signature_hash) != 32:
            raise ComparisonError(f"{path}:{row_number}: invalid signature hash")
        if expected_id in seen:
            raise ComparisonError(f"{path}:{row_number}: duplicate input_id")
        seen.add(expected_id)
        measurements.append(Measurement(
            parameter=parameter,
            implementation=expected_implementation,
            case_number=case_number,
            input_id=expected_id,
            signature_sha256=row["signature_sha256"],
            algorithm_cycles=cycles,
            attempts=attempts,
        ))
    return measurements


def build_report(
    hardware: Sequence[Measurement], software: Sequence[Measurement]
) -> str:
    hardware_by_id = {item.input_id: item for item in hardware}
    software_by_id = {item.input_id: item for item in software}
    if len(hardware_by_id) != len(hardware) or len(software_by_id) != len(software):
        raise ComparisonError("measurement inputs must be unique")
    if hardware_by_id.keys() != software_by_id.keys():
        missing_software = hardware_by_id.keys() - software_by_id.keys()
        missing_hardware = software_by_id.keys() - hardware_by_id.keys()
        raise ComparisonError(
            "hardware/software input sets differ "
            f"(missing software={len(missing_software)}, "
            f"missing hardware={len(missing_hardware)})"
        )
    parameters = {item.parameter for item in (*hardware, *software)}
    if len(parameters) != 1:
        raise ComparisonError("each comparison must contain one security level")
    parameter = parameters.pop()

    pairs: list[tuple[Measurement, Measurement]] = []
    for hardware_item in hardware:
        software_item = software_by_id[hardware_item.input_id]
        if hardware_item.signature_sha256 != software_item.signature_sha256:
            raise ComparisonError(
                f"signature differs for input {hardware_item.input_id[:12]}"
            )
        if hardware_item.attempts != software_item.attempts:
            raise ComparisonError(
                f"attempt count differs for input {hardware_item.input_id[:12]}: "
                f"hardware={hardware_item.attempts}, "
                f"software={software_item.attempts}"
            )
        pairs.append((hardware_item, software_item))

    hardware_cycles = [pair[0].algorithm_cycles for pair in pairs]
    software_cycles = [pair[1].algorithm_cycles for pair in pairs]
    paired_speedups = [
        software_item.algorithm_cycles / hardware_item.algorithm_cycles
        for hardware_item, software_item in pairs
    ]
    attempts = [pair[0].attempts for pair in pairs]
    hardware_mean = statistics.fmean(hardware_cycles)
    software_mean = statistics.fmean(software_cycles)

    lines = [
        f"# ML-DSA-{parameter} Sign 同输入板端性能比较",
        "",
        f"- 配对样本数：{len(pairs)}",
        "- 平台：同一 E203 板端，算法计时均使用 `mcycle`。",
        "- 配对检查：输入、完整签名参考摘要和拒绝采样尝试次数全部一致。",
        "",
        "| 实现 | 平均周期 | 中位数周期 | 最小周期 | 最大周期 |",
        "| --- | ---: | ---: | ---: | ---: |",
        (
            f"| 纯软件 | {software_mean:.1f} | "
            f"{statistics.median(software_cycles):.1f} | "
            f"{min(software_cycles)} | {max(software_cycles)} |"
        ),
        (
            f"| 硬件协同 | {hardware_mean:.1f} | "
            f"{statistics.median(hardware_cycles):.1f} | "
            f"{min(hardware_cycles)} | {max(hardware_cycles)} |"
        ),
        "",
        "| 指标 | 结果 |",
        "| --- | ---: |",
        f"| 总工作量加速比（纯软件周期总和 / 硬件周期总和） | {software_mean / hardware_mean:.4f}x |",
        f"| 单样本加速比中位数 | {statistics.median(paired_speedups):.4f}x |",
        f"| 单样本加速比范围 | {min(paired_speedups):.4f}x - {max(paired_speedups):.4f}x |",
        f"| 实测平均尝试次数 | {statistics.fmean(attempts):.4f} |",
        "",
        "## 按尝试次数分组",
        "",
        "| 尝试次数 | 样本数 | 纯软件平均周期 | 硬件平均周期 | 分组加速比 |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    for attempt_count in sorted(set(attempts)):
        group = [pair for pair in pairs if pair[0].attempts == attempt_count]
        group_hardware = statistics.fmean(
            pair[0].algorithm_cycles for pair in group
        )
        group_software = statistics.fmean(
            pair[1].algorithm_cycles for pair in group
        )
        lines.append(
            f"| {attempt_count} | {len(group)} | {group_software:.1f} | "
            f"{group_hardware:.1f} | {group_software / group_hardware:.4f}x |"
        )
    lines.extend([
        "",
        "加速比采用成对输入的总工作量比值。不要分别使用两批随机输入的平均值",
        "相除，因为两批拒绝采样次数分布不同会给结果带来额外偏差。",
        "",
    ])
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare paired E203 software and hardware ML-DSA Sign cycles."
    )
    parser.add_argument("--hardware", type=Path, required=True)
    parser.add_argument("--software", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        hardware = load_measurements(args.hardware, "hardware")
        software = load_measurements(args.software, "software")
        report = build_report(hardware, software)
        if args.output is not None:
            try:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(report, encoding="utf-8")
            except OSError as error:
                raise ComparisonError(
                    f"cannot write report {args.output}: {error}"
                ) from error
            print(f"Wrote paired comparison report to {args.output}")
        print(report)
        return 0
    except ComparisonError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
