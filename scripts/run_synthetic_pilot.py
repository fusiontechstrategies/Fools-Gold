"""Repeatable assurance exercise. Everything below is synthetic and local."""

import json
import tempfile
from datetime import timedelta
from pathlib import Path

from fools_gold.core import Engine, Registry, stamp
from tests.test_pilot import NOW, registry, s3, windows


def run():
    with tempfile.TemporaryDirectory(prefix="fools-gold-synthetic-") as folder:
        engine = Engine(Registry(registry()), Path(folder) / "evidence.sqlite")
        try:
            scenarios = []
            for name, event in (
                ("GovCloud synthetic object read", s3()),
                ("Windows synthetic document read", windows()),
            ):
                result = engine.process(event, NOW)
                if result["decision"] != "alert":
                    raise RuntimeError(f"missed synthetic trigger: {name}")
                engine.acknowledge(
                    result["alert"]["alert_id"],
                    "synthetic-analyst",
                    NOW + timedelta(seconds=30),
                )
                scenarios.append(
                    {
                        "name": name,
                        "decoy_id": result["decoy_id"],
                        "passed": True,
                        "last_successful_offline_test": stamp(NOW),
                        "alert_id": result["alert"]["alert_id"],
                        "telemetry_delay_seconds": result["alert"][
                            "telemetry_delay_seconds"
                        ],
                    }
                )
            benign = s3("synthetic-authorized-backup")
            benign["userIdentity"]["arn"] = registry()["decoys"][0]["exceptions"][0][
                "actor"
            ]
            if engine.process(benign, NOW)["decision"] != "expected_access":
                raise RuntimeError(
                    "authorized synthetic read was not classified correctly"
                )
            if engine.process(s3(), NOW)["decision"] != "duplicate":
                raise RuntimeError("replay deduplication failed")
            summary = engine.report()
            summary.update(
                synthetic=True,
                scenarios=scenarios,
                missed_synthetic_triggers=0,
                notice="Fixed fixture clock and simulated analyst acknowledgment. No live collection or SIEM delivery tested.",
            )
            return summary
        finally:
            engine.close()


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
