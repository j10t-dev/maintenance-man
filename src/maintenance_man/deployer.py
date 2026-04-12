from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from maintenance_man.env import project_env


class BuildError(Exception):
    pass


class DeployError(Exception):
    pass


def _run_script(
    command: str,
    project_name: str,
    project_path: Path,
    error_cls: type[Exception],
    label: str,
) -> None:
    """Run a shell command with live output. Raises error_cls on failure."""
    try:
        result = subprocess.run(
            command,
            cwd=project_path,
            shell=True,
            executable="/bin/bash",
            env=project_env(),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        msg = f"{label} timed out for {project_name} (exceeded 600s)"
        raise error_cls(msg) from None
    if result.returncode != 0:
        msg = f"{label} failed for {project_name} (exit code {result.returncode})"
        raise error_cls(msg)


def run_build(project_name: str, build_command: str, project_path: Path) -> None:
    """Run a project's build command. Raises BuildError on failure."""
    _run_script(build_command, project_name, project_path, BuildError, "Build")


def run_deploy(project_name: str, deploy_command: str, project_path: Path) -> None:
    """Run a project's deploy command. Raises DeployError on failure."""
    _run_script(deploy_command, project_name, project_path, DeployError, "Deploy")


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
        except (urllib.error.URLError, TimeoutError):
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2

    return HealthCheckResult(
        is_up=False,
        error=f"Could not reach healthchecker after {max_retries} attempts",
    )
