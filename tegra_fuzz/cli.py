"""Command-line interface for tegra_fuzz."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, rcm
from .model import Outcome, TestCase
from .corpus import Corpus, load_case
from .engine import Fuzzer, FuzzConfig
from .transport import UsbTransport, FakeTransport, TransportError


BANNER = f"""tegra_fuzz {__version__} — live RCM USB fuzzer
  target     : VID 0x{rcm.VID:04x} PID 0x{rcm.PID:04x} (Tegra X1 APX / recovery mode)
  surface    : bulk OUT 0x{rcm.EP_OUT:02x}, bulk IN 0x{rcm.EP_IN:02x}, EP0 control
  scope      : sends malformed RCM messages / control transfers and observes the
               device; it does not run an exploit or generate a payload.
  reminder   : the RCM bootROM is in mask ROM; malformed input can hang/reset it
               until RCM is re-entered, but cannot permanently modify it."""


def _filter_seeds(domain: str) -> list[TestCase]:
    seeds = rcm.seed_cases()
    if domain == "both":
        return seeds
    return [s for s in seeds if s.kind == domain]


def _make_printer(quiet: bool):
    def printer(result):
        o = result.outcome
        if o.interesting or (not quiet):
            tag = o.value.upper()
            marker = "!!" if o.interesting else "  "
            print(f"{marker} [{result.iteration:>6}] {tag:<11} {result.case.summary()}"
                  + (f"  resp={len(result.response)}B" if result.response else ""),
                  flush=True)
    return printer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tegra_fuzz",
        description="Live USB fuzzer for the Tegra X1 RCM (recovery mode) interface. "
                    "Research tool: generates malformed input and records anomalies; "
                    "it is not an exploit or payload generator.",
    )
    p.add_argument("--version", action="version", version=f"tegra_fuzz {__version__}")
    p.add_argument("-n", "--iterations", type=int, default=1000,
                   help="number of fuzz cases to run (default: 1000)")
    p.add_argument("--seed", type=int, default=0,
                   help="RNG seed for a reproducible run (default: 0)")
    p.add_argument("--domain", choices=("rcm", "control", "both"), default="both",
                   help="which seed surface to fuzz (default: both)")
    p.add_argument("--timeout", type=int, default=1000,
                   help="per-transfer timeout in ms (default: 1000)")
    p.add_argument("--probe-timeout", type=int, default=500,
                   help="liveness-probe timeout in ms (default: 500)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="delay between cases in ms (default: 0)")
    p.add_argument("--max-crashes", type=int, default=0,
                   help="stop after N interesting findings (0 = unlimited)")
    p.add_argument("--out", type=Path, default=Path("findings"),
                   help="output directory for crashes + session log (default: ./findings)")
    p.add_argument("--read-response", action="store_true",
                   help="read EP IN after each rcm send (slower, catches some leaks)")
    p.add_argument("--stop-on-disconnect", action="store_true",
                   help="halt on the first reset/hang/disconnect instead of re-opening")
    p.add_argument("--no-reopen", action="store_true",
                   help="do not try to re-acquire the device after a reset")
    p.add_argument("--skip-seeds", action="store_true",
                   help="skip the seed corpus and jump straight to mutations")
    p.add_argument("--dry-run", action="store_true",
                   help="run the whole pipeline against a fake transport (no hardware)")
    p.add_argument("--replay", type=Path, default=None,
                   help="load one saved case JSON and run it once")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print interesting findings, not every case")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    transport = FakeTransport() if args.dry_run else UsbTransport()
    seeds = _filter_seeds(args.domain)
    corpus = Corpus(args.out, seeds=seeds)

    config = FuzzConfig(
        iterations=args.iterations,
        seed=args.seed,
        timeout_ms=args.timeout,
        probe_timeout_ms=args.probe_timeout,
        delay_ms=args.delay,
        max_crashes=args.max_crashes,
        reopen=not args.no_reopen,
        read_rcm_response=args.read_response,
        stop_on_disconnect=args.stop_on_disconnect,
        skip_seeds=args.skip_seeds,
    )

    if not args.dry_run:
        print(BANNER, file=sys.stderr)

    # Open the device up front so permission/presence problems are clear.
    try:
        transport.open()
    except TransportError as exc:
        if exc.kind == "no_device":
            print("error: Tegra APX device not found — put the console in RCM mode "
                  "and connect it.", file=sys.stderr)
        elif exc.kind == "permission":
            print("error: permission denied opening the device — run with sudo or add "
                  "yourself to the owning udev group.", file=sys.stderr)
        else:
            print(f"error: could not open device: {exc}", file=sys.stderr)
        return 2

    log_path = Path(args.out) / "session.jsonl"
    fuzzer = Fuzzer(transport, corpus, config, log_path=log_path,
                    on_result=_make_printer(args.quiet))

    try:
        if args.replay is not None:
            case = load_case(args.replay)
            result = fuzzer.execute(case)
            _make_printer(False)(result)
            return 0
        summary = fuzzer.run()
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        summary = None
    finally:
        transport.close()

    if summary is not None:
        print("\n=== summary ===", file=sys.stderr)
        print(f"iterations : {summary.iterations}", file=sys.stderr)
        print(f"findings   : {summary.crashes}  -> {corpus.crash_dir}", file=sys.stderr)
        print(f"stopped    : {summary.stopped_reason}", file=sys.stderr)
        for name, count in sorted(summary.counts.items()):
            print(f"  {name:<12} {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
