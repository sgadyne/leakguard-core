"""Command-line adapter for the shared LeakGuard scan service."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from .api import ConfigurationError, ScanConfig, Scanner
from .models import DecisionVerdict, ErrorCode, ScanLimits, ScanPolicy
from . import presentation


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in {"scan", "audit", "drain", "doctor"}:
        return _run_legacy(arguments, argv is None)

    parser = _parser()
    args = parser.parse_args(arguments)
    try:
        config = _load_config(args.config)
        config_values = config.to_mapping()
        if args.command == 'doctor':
            return _doctor(config_values, args.format)
        from . import settings

        state_dir = Path(args.state_dir).expanduser() if args.state_dir else settings.state_directory()
        limits = ScanLimits(
            deadline_seconds=args.budget_seconds,
            max_files=args.max_files,
            max_file_bytes=config_values["max_file_bytes"],
            detector_timeout_seconds=config_values["scan_timeout_seconds"],
            worker_memory_bytes=config_values['worker_memory_bytes'],
        )
        with Scanner.open(config=config, state_dir=state_dir) as scanner:
            if args.command == "scan":
                report = scanner.scan_paths(
                    tuple(Path(path) for path in args.paths),
                    policy=ScanPolicy.inventory(),
                    limits=limits,
                    use_cache=args.use_cache,
                )
            elif args.command == "audit":
                report = scanner.audit(args.scope, limits=limits, use_cache=args.use_cache)
            else:
                report = scanner.drain(limits=limits, use_cache=args.use_cache)
    except ConfigurationError as error:
        print(f"LeakGuard: {error.code} ({error.field})", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("LeakGuard: configuration-invalid", file=sys.stderr)
        return 2
    except Exception as error:
        code = getattr(error, "code", None)
        if isinstance(code, ErrorCode):
            code = code.value
        if not isinstance(code, str) or code not in {item.value for item in ErrorCode}:
            code = ErrorCode.STATE_FAILED.value
        print(f"LeakGuard: {code}", file=sys.stderr)
        return 2

    if args.format == "json":
        sys.stdout.write(report.to_json() + "\n")
    else:
        print(presentation.render(report))

    if report.decision.verdict is DecisionVerdict.INCOMPLETE:
        return 2
    if args.fail_on == "block" and (report.decision.verdict is DecisionVerdict.BLOCK or report.counts.block_findings):
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="leakguard")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Check worker policy and SQLite checkpoint support")
    doctor.add_argument("--config", help="External JSON configuration (also accepts LEAKGUARD_CONFIG)")
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    scan = commands.add_parser("scan", help="Scan files or directories through the shared service")
    scan.add_argument("paths", nargs="+", help="Files and directories explicitly selected for scanning")
    audit = commands.add_parser("audit", help="Advance a resumable configured scope audit")
    audit.add_argument("scope")
    drain = commands.add_parser("drain", help="Process one bounded notification-queue batch")
    for command, deadline, files in ((scan, 120, 1000), (audit, 600, 3000), (drain, 45, 150)):
        command.add_argument("--config", help="External JSON configuration (also accepts LEAKGUARD_CONFIG)")
        command.add_argument("--state-dir", help="Private writable runtime state directory")
        command.add_argument("--format", choices=("text", "json"), default="text")
        command.set_defaults(use_cache=command is not drain)
        command.add_argument("--no-cache", dest="use_cache", action="store_false", help="Bypass semantic result reuse")
        if command is drain:
            command.add_argument("--use-cache", dest="use_cache", action="store_true", help="Reuse complete eligible results")
        command.add_argument("--fail-on", choices=("block",), help="Exit 1 when a blocking finding exists")
        command.add_argument("--budget-seconds", type=_positive_int, default=deadline)
        command.add_argument("--max-files", type=_positive_int, default=files)
    return parser


def _doctor(config: dict[str, object], output_format: str) -> int:
    import shutil
    from .scan_store import SQLiteScanStore
    from ._supervision import worker_capabilities
    execution = worker_capabilities(config['worker_policy'])
    probes = []
    checkpoint = False
    try:
        # Probe the actual memory-only factory, including TEMP_STORE compile
        # options and journal settings; method existence alone is insufficient.
        original = SQLiteScanStore.from_memory()
        probes.append(original)
        restored = SQLiteScanStore.from_memory(original.serialize())
        probes.append(restored)
        checkpoint = True
    except Exception:
        pass
    finally:
        for probe in probes:
            probe.close()
    selected = config.get('gitleaks_executable') or os.environ.get('LEAKGUARD_GITLEAKS') or 'gitleaks'
    backend_available = bool(shutil.which(selected))
    from .navigation import Navigation, NavigationError
    try:
        with Navigation(helper=config.get('navigation_helper')) as navigator:
            navigation = dict(navigator.capabilities(),
                              same_filesystem=config['navigation_same_filesystem'])
        navigation_available = True
    except NavigationError as error:
        navigation = {'backend': 'rust-ignore', 'status': 'unavailable', 'code': error.code}
        navigation_available = False
    from . import plugins
    try:
        extensions = plugins.preflight(config.get('plugins', ()), worker_policy=config['worker_policy'],
                                        memory_bytes=config['worker_memory_bytes'])
    except plugins.PluginError as error:
        extensions = ({'component': 'configured-component', 'ready': False, 'code': error.code},)
    healthy = execution['available'] and checkpoint and backend_available and navigation_available and all(item['ready'] for item in extensions)
    result = {'schema_version': 1, 'healthy': healthy, 'execution': execution,
              'sqlite_serialization': checkpoint, 'backend_available': backend_available,
              'detection_profile': config['detection_profile'],
              'scan_workers': config['scan_workers'], 'navigation': navigation,
              'extensions': extensions}
    if output_format == 'json':
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    else:
        print('LeakGuard doctor: ' + ('ready' if healthy else 'unavailable requirements'))
        print(f"Worker policy: {execution['policy']}; memory: {execution['memory_enforcement']}")
        if execution['memory_enforcement'] == 'rss-watchdog':
            print('RSS is sampled; this is not a hard allocation limit.')
        print(f"SQLite encrypted checkpoint support: {'available' if checkpoint else 'unavailable'}")
        print(f"Gitleaks executable: {'available' if backend_available else 'unavailable'}")
    return 0 if healthy else 2


def _load_config(explicit_path: str | None) -> ScanConfig:
    path = explicit_path or os.environ.get("LEAKGUARD_CONFIG")
    if path:
        config = ScanConfig.from_file(Path(path).expanduser())
        values = config.to_mapping()
    else:
        values = {}
    selected_gitleaks = os.environ.get("LEAKGUARD_GITLEAKS")
    if selected_gitleaks:
        values["gitleaks_executable"] = selected_gitleaks
    return ScanConfig.from_mapping(values)


def _positive_int(raw: str) -> int:
    try:
        value = int(raw, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _run_legacy(arguments: list[str], use_process_argv: bool) -> int:
    """Keep the existing audit/watch/drain/Git subcommands as compatibility paths."""
    from . import engine

    if use_process_argv:
        return engine.run()
    previous = sys.argv
    try:
        sys.argv = [previous[0], *arguments]
        return engine.run()
    finally:
        sys.argv = previous


if __name__ == "__main__":
    raise SystemExit(main())
