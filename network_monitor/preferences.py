import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Preferences:
    poll_interval_seconds: int = 3
    stats_window_hours: int = 1
    graph_window_hours: int = 24
    report_window_hours: int = 24
    graph_host_ids: list[int] | None = None
    alerts_enabled: bool = True
    alert_failure_threshold: int = 2


def load_preferences(path: str | Path) -> Preferences:
    preferences_path = Path(path)
    if not preferences_path.exists():
        return Preferences()
    try:
        values = json.loads(preferences_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read preferences at {preferences_path}: {error}") from error
    if not isinstance(values, dict):
        raise ValueError("Preferences must be a JSON object.")

    defaults = asdict(Preferences())
    unknown_keys = set(values) - set(defaults)
    if unknown_keys:
        raise ValueError(f"Unknown preference fields: {', '.join(sorted(unknown_keys))}")
    defaults.update(values)
    preferences = Preferences(**defaults)
    _validate(preferences)
    return preferences


def save_preferences(path: str | Path, preferences: Preferences) -> None:
    _validate(preferences)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(asdict(preferences), temporary_file, indent=2)
            temporary_file.write("\n")
        os.replace(temporary_path, destination)
    except OSError:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
        raise


def _validate(preferences: Preferences) -> None:
    if type(preferences.poll_interval_seconds) is not int or not (
        1 <= preferences.poll_interval_seconds <= 3600
    ):
        raise ValueError("poll_interval_seconds must be between 1 and 3600.")
    if type(preferences.stats_window_hours) is not int or not (
        1 <= preferences.stats_window_hours <= 168
    ):
        raise ValueError("stats_window_hours must be between 1 and 168.")
    if type(preferences.graph_window_hours) is not int or not (
        1 <= preferences.graph_window_hours <= 720
    ):
        raise ValueError("graph_window_hours must be between 1 and 720.")
    if type(preferences.report_window_hours) is not int or not (
        1 <= preferences.report_window_hours <= 720
    ):
        raise ValueError("report_window_hours must be between 1 and 720.")
    if not isinstance(preferences.alerts_enabled, bool):
        raise ValueError("alerts_enabled must be a boolean.")
    if type(preferences.alert_failure_threshold) is not int or not (
        1 <= preferences.alert_failure_threshold <= 20
    ):
        raise ValueError("alert_failure_threshold must be between 1 and 20.")
    if preferences.graph_host_ids is not None and (
        not isinstance(preferences.graph_host_ids, list)
        or any(type(host_id) is not int or host_id < 1 for host_id in preferences.graph_host_ids)
    ):
        raise ValueError("graph_host_ids must be a list of positive host IDs or null.")
