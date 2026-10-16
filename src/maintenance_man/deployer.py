from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


class BuildError(Exception):
    pass


class DeployError(Exception):
    pass


@dataclass
class HealthCheckResult:
    is_up: bool
    error: str | None = None


def check_health(
    base_url: str,
    service_name: str,
    *,
    max_retries: int = 5,
    initial_delay: float = 2.0,
) -> HealthCheckResult:
    """Poll healthchecker for service status with exponential backoff."""
    url = f"{base_url.rstrip('/')}/api/status/{service_name}"
    delay = initial_delay

    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
                return HealthCheckResult(is_up=data.get("is_up", False))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return HealthCheckResult(
                    is_up=False,
                    error=f"Service '{service_name}' not found in healthchecker",
                )
            if e.code >= 500 and attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            return HealthCheckResult(is_up=False, error=f"HTTP {e.code}: {e.reason}")
        except json.JSONDecodeError:
            return HealthCheckResult(
                is_up=False,
                error="Healthchecker returned non-JSON response",
            )
        except urllib.error.URLError, TimeoutError:
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2

    return HealthCheckResult(
        is_up=False,
        error=f"Could not reach healthchecker after {max_retries} attempts",
    )
