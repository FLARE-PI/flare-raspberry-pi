"""Command-line interface for the offline MuSimA adapter harness."""

import argparse
import json
import sys
from pathlib import Path

from .emit import DEFAULT_BENCHMARK_ROOT, DEFAULT_UID_BASE, convert_dataset
from .parser import load_dataset
from .trace import compile_base_trace, compile_correctness
from .validate import validate_all_tuples, validate_base_log


def _print(data):
    sys.stdout.write(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _dataset(args):
    return load_dataset(args.source, args.dataset_id)


def command_inspect(args):
    dataset = _dataset(args)
    _print({
        "deny_rule_count": len(dataset.deny_rules),
        "environment_count": len(dataset.environments),
        "logical_dataset_id": dataset.logical_id,
        "object_count": len(dataset.objects),
        "permit_rule_count": len(dataset.permit_rules),
        "source_filename": dataset.source_filename,
        "source_sha256": dataset.source_sha256,
        "subject_count": len(dataset.subjects),
    })


def command_convert(args):
    dataset = _dataset(args)
    convert_dataset(dataset, args.output, args.uid_base, args.benchmark_root, args.repository_root)
    _print({"generated_dir": str(Path(args.output)), "logical_dataset_id": dataset.logical_id})


def command_validate(args):
    _print(validate_all_tuples(_dataset(args), args.source, args.generated))


def command_compile_correctness(args):
    count = compile_correctness(_dataset(args), args.source, args.generated)
    _print({"requests_compiled": count})


def command_compile_trace(args):
    _print(compile_base_trace(_dataset(args), args.source, args.log, args.generated))


def command_validate_log(args):
    _print(validate_base_log(_dataset(args), args.source, args.log))


def _source_arguments(parser):
    parser.add_argument("--source", type=Path, required=True, help="MuSimA ZIP input")
    parser.add_argument("--dataset-id", help="Stable logical dataset identifier")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline MuSimA adapter and workload compiler")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect", help="validate and summarize a MuSimA ZIP")
    _source_arguments(inspect)
    inspect.set_defaults(func=command_inspect)

    convert = subparsers.add_parser("convert", help="emit deterministic maintained-ABAC configuration")
    _source_arguments(convert)
    convert.add_argument("--output", type=Path, required=True)
    convert.add_argument("--uid-base", type=int, default=DEFAULT_UID_BASE)
    convert.add_argument("--benchmark-root", default=DEFAULT_BENCHMARK_ROOT)
    convert.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[2])
    convert.set_defaults(func=command_convert)

    validate = subparsers.add_parser("validate", help="compare source and emitted policies to source ACM")
    _source_arguments(validate)
    validate.add_argument("--generated", type=Path, required=True)
    validate.set_defaults(func=command_validate)

    correctness = subparsers.add_parser("compile-correctness", help="compile exhaustive CORRECTNESS trace")
    _source_arguments(correctness)
    correctness.add_argument("--generated", type=Path, required=True)
    correctness.set_defaults(func=command_compile_correctness)

    trace = subparsers.add_parser("compile-trace", help="compile ordered and grouped BASE-MIXED traces")
    _source_arguments(trace)
    trace.add_argument("--generated", type=Path, required=True)
    trace.add_argument("--log", type=Path, required=True)
    trace.set_defaults(func=command_compile_trace)

    log = subparsers.add_parser("validate-log", help="compare a BASE-MIXED log with the source ACM")
    _source_arguments(log)
    log.add_argument("--log", type=Path, required=True)
    log.set_defaults(func=command_validate_log)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.exit(2, "error: {}\n".format(error))


if __name__ == "__main__":
    main()
