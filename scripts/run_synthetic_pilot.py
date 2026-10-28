"""Repeatable assurance exercise. Everything below is synthetic and local."""

import json

from fools_gold.assurance import run_check
from tests.test_pilot import NOW

if __name__ == "__main__":
    print(json.dumps(run_check(now=NOW), indent=2))
