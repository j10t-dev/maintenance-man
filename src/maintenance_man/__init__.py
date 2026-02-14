__version__ = "0.1.0"


def sanitise_project_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_").replace("..", "_")
