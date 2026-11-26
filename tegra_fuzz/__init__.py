"""tegra_fuzz — a live USB fuzzer for the Tegra X1 RCM (recovery mode) interface.

Research tooling for probing the Tegra bootROM USB recovery protocol on hardware
you own. It *generates malformed input and observes device behaviour* (stalls,
hangs, resets, unexpected responses) — it is a fuzzer, not a packaged exploit or
payload generator. Every test case is fully serialisable so any anomaly is
reproducible from its saved record.

The RCM bootROM lives in mask ROM and is reset on power-cycle; malformed input
can make it hang or drop off the bus until RCM is re-entered, but cannot
permanently modify it.
"""

__version__ = "0.1.0"
