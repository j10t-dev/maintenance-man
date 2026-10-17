from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from maintenance_man import __version__, cli
from maintenance_man.config import ConfigError
from maintenance_man.deployer import BuildError
from maintenance_man.gradle import GradleError
from maintenance_man.outdated import OutdatedCheckError
from maintenance_man.scanner import ScanError
from maintenance_man.services import WorkflowError
from maintenance_man.services.update import UpdateSetupError
from maintenance_man.vcs import RevisionError
from tests.conftest import configure_fake_vcs, run_mm, write_config


@pytest.mark.parametrize(
    ("argv", "service_seam", "error", "expected_code"),
    [
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            ScanError("trivy failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            GradleError("report failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            RevisionError("jj failed"),
            1,
        ),
        (
            ("scan", "vulnerable"),
            "maintenance_man.services.scan.scan_one",
            OutdatedCheckError("uv failed"),
            1,
        ),
        (
            ("update", "vulnerable"),
            "maintenance_man.services.update.update_project",
            WorkflowError("refused"),
            1,
        ),
        (
            ("update", "vulnerable"),
            "maintenance_man.services.update.update_project",
            UpdateSetupError("refused"),
            1,
        ),
        (
            ("build", "deployable"),
            "maintenance_man.services.deploy.build_project",
            BuildError("make failed"),
            6,
        ),
    ],
    ids=[
        "scan-error",
        "gradle-error",
        "revision-error",
        "outdated-check-error",
        "workflow-error",
        "workflow-error-subclass",
        "build-error",
    ],
)
def test_given_a_service_refusal_when_a_command_runs_then_it_maps_to_one_error_line(
    mm_home_with_projects: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, str],
    service_seam: str,
    error: Exception,
    expected_code: int,
) -> None:
    configure_fake_vcs(mm_home_with_projects, tmp_path, monkeypatch)
    monkeypatch.setattr(service_seam, MagicMock(side_effect=error))

    code = run_mm(*argv)
    error_lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("Error:")
    ]

    assert (code, error_lines) == (
        expected_code,
        [f"Error: {error}"],
    )


class TestHelp:
    def test_help_contains_description(self, capsys: pytest.CaptureFixture[str]):
        assert run_mm("--help") == 0
        assert "maintenance" in capsys.readouterr().out.lower()


class TestVersion:
    def test_version_prints_version(self, capsys: pytest.CaptureFixture[str]):
        assert run_mm("--version") == 0
        assert __version__ in capsys.readouterr().out


class TestInitCommand:
    def test_init_uses_redirected_home(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        assert run_mm("init") == 0
        out = capsys.readouterr().out.replace("\n", "")
        assert str(mm_home) in out
        assert (mm_home / "config.toml").is_file()

    def test_init_prints_bracketed_home_path_literally(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "[home]"
        output = StringIO()
        monkeypatch.setattr("maintenance_man.paths.MM_HOME", home)
        monkeypatch.setattr(
            cli, "console", Console(file=output, width=220, color_system=None)
        )

        assert run_mm("init") == 0
        assert str(home) in output.getvalue()


def test_fatal_prints_bracketed_plain_text_literally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = StringIO()
    monkeypatch.setattr(
        cli, "console", Console(file=output, width=220, color_system=None)
    )

    monkeypatch.setattr(
        cli, "_load_cfg", MagicMock(side_effect=ConfigError("bad [projects.x]"))
    )

    assert run_mm("scan") == 1
    assert "Error: bad [projects.x]" in output.getvalue()


def test_config_validation_error_keeps_pydantic_type_suffix(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    write_config(mm_home, '[projects.api]\npackage_manager = "uv"\n')

    assert run_mm("scan") == 1

    assert "[type=missing" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("deploy", "Add deploy_command to [projects.api] in ~/.mm/config.toml."),
        ("build", "Add build_command to [projects.api]"),
        ("test", "Add test_unit to [projects.api]"),
    ],
)
def test_missing_command_error_keeps_config_table_literal(
    mm_home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    expected: str,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    mm_home.mkdir(parents=True)
    write_config(
        mm_home,
        f'[projects.api]\npath = "{project}"\npackage_manager = "uv"\n',
    )

    assert run_mm(command, "api") == 1

    assert expected in " ".join(capsys.readouterr().out.split())


def test_deploy_check_hint_keeps_defaults_table_literal(
    mm_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mm_home.mkdir(parents=True)
    write_config(mm_home, "[defaults]\n")

    assert run_mm("deploy", "--check") == 0

    assert "configured in [defaults]" in capsys.readouterr().out


class TestDeployCommand:
    def test_deploy_no_project_is_mass_mode(self, mm_home: Path):
        """Deploy with no project triggers mass mode (exits OK with no projects)."""
        mm_home.mkdir(parents=True, exist_ok=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("deploy") == 0

    def test_deploy_unknown_project_exits_error(self, mm_home):
        """Deploy with unknown project exits with ERROR."""
        assert run_mm("deploy", "project-alpha") == 1


class TestTodoCommand:
    """Tests for mm todo."""

    @pytest.fixture()
    def mm_home_with_todos(self, mm_home: Path) -> Path:
        """mm_home with two projects: 'alpha' has a TODO.md, 'beta' does not."""
        alpha_dir = mm_home.parent / "alpha"
        alpha_dir.mkdir()
        (alpha_dir / "TODO.md").write_text("- Fix the widget\n- Refactor utils\n")

        beta_dir = mm_home.parent / "beta"
        beta_dir.mkdir()

        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(
            mm_home,
            f'[projects.alpha]\npath = "{alpha_dir}"\npackage_manager = "uv"\n\n'
            f'[projects.beta]\npath = "{beta_dir}"\npackage_manager = "uv"\n',
        )
        return mm_home

    def test_todo_all_shows_content_and_missing_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo pipes items for alpha and notices that beta has none."""
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "alpha\t1\t- Fix the widget",
            "alpha\t2\t- Refactor utils",
        ]
        assert captured.err == "1 projects have no TODO items: beta\n"

    def test_todo_all_shows_empty_message(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo collapses blank and missing TODO.md files into one notice."""
        alpha_dir = mm_home_with_todos.parent / "alpha"
        (alpha_dir / "TODO.md").write_text("   \n\n  ")
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "2 projects have no TODO items: alpha, beta\n"

    def test_todo_single_project_shows_content(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> shows that project's TODO.md."""
        assert run_mm("todo", "alpha") == 0
        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            "alpha\t1\t- Fix the widget",
            "alpha\t2\t- Refactor utils",
        ]
        assert captured.err == ""

    def test_todo_single_project_no_file(
        self, mm_home_with_todos: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo <project> with no TODO.md notices on stderr, exits 0."""
        assert run_mm("todo", "beta") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "No TODO items in beta\n"

    def test_todo_unknown_project_exits_error(self, mm_home_with_todos: Path):
        """mm todo <unknown> exits with error (config error, not missing file)."""
        assert run_mm("todo", "nonexistent") == 1

    def test_todo_no_projects_configured(
        self, mm_home: Path, capsys: pytest.CaptureFixture[str]
    ):
        """mm todo with no projects configured notices with a hint and exits 0."""
        mm_home.mkdir(parents=True)
        (mm_home / "scan-results").mkdir()
        (mm_home / "workspaces").mkdir()
        write_config(mm_home, "[defaults]\nmin_version_age_days = 7\n")
        assert run_mm("todo") == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err.splitlines() == [
            "No projects configured",
            "hint: add projects to ~/.mm/config.toml",
        ]

    def test_given_bracketed_name_and_markdown_when_todo_runs_then_both_print_literally(
        self, mm_home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "TODO.md").write_text("# Keep *Markdown*\n", encoding="utf-8")
        mm_home.mkdir(parents=True)
        write_config(
            mm_home,
            f'[projects."a[b]"]\npath = "{project}"\npackage_manager = "uv"\n',
        )

        assert run_mm("todo", "a[b]") == 0

        assert capsys.readouterr().out == "a[b]\t1\t# Keep *Markdown*\n"
