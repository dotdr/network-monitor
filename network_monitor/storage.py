import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Host, HostSummary, ProbeResult, Sample


class MonitorDatabase:
    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            path = Path.home() / ".network-monitor" / "history.sqlite3"
        self.path = Path(path)
        self.settings_path = self.path.with_name("settings.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout = 30000")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("ATTACH DATABASE ? AS config", (str(self.settings_path),))
        self.connection.execute("PRAGMA config.journal_mode = WAL")
        self.connection.execute("PRAGMA config.synchronous = NORMAL")
        try:
            self._create_schema()
        except Exception:
            self.connection.close()
            raise

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS config.hosts (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(address, port)
            );
            CREATE TABLE IF NOT EXISTS config.preferences (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                values_json TEXT NOT NULL
            );
            """
        )
        self._migrate_legacy_hosts()
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                success INTEGER NOT NULL,
                latency_ms REAL,
                method TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS samples_checked_at_idx
                ON samples(checked_at DESC);
            CREATE INDEX IF NOT EXISTS samples_host_checked_idx
                ON samples(host_id, checked_at DESC);
            """
        )
        self.connection.commit()

    def _migrate_legacy_hosts(self) -> None:
        tables = {
            row["name"]
            for row in self.connection.execute(
                "SELECT name FROM main.sqlite_master WHERE type = 'table'"
            )
        }
        if "hosts" not in tables:
            return

        legacy_hosts = self.connection.execute(
            "SELECT id, address, port, enabled FROM main.hosts"
        ).fetchall()
        host_id_map: dict[int, int] = {}
        for row in legacy_hosts:
            self.connection.execute(
                """
                INSERT INTO config.hosts(address, port, enabled)
                VALUES (?, ?, ?)
                ON CONFLICT(address, port) DO NOTHING
                """,
                (row["address"], row["port"], row["enabled"]),
            )
            config_host = self.connection.execute(
                "SELECT id FROM config.hosts WHERE address = ? AND port = ?",
                (row["address"], row["port"]),
            ).fetchone()
            host_id_map[row["id"]] = config_host["id"]
        self.connection.commit()

        if "samples" in tables:
            sample_columns = {
                row["name"]
                for row in self.connection.execute("PRAGMA main.table_info(samples)")
            }
            if not {"address", "port"}.issubset(sample_columns):
                self.connection.execute("PRAGMA foreign_keys = OFF")
                self.connection.execute("DROP TABLE IF EXISTS main.samples_migrated")
                self.connection.execute(
                    """
                    CREATE TEMP TABLE legacy_host_id_map (
                        old_id INTEGER PRIMARY KEY,
                        new_id INTEGER NOT NULL
                    )
                    """
                )
                self.connection.executemany(
                    "INSERT INTO legacy_host_id_map(old_id, new_id) VALUES (?, ?)",
                    host_id_map.items(),
                )
                self.connection.commit()
                self.connection.execute("BEGIN")
                self.connection.execute(
                    """
                    CREATE TABLE main.samples_migrated (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER NOT NULL,
                        address TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        checked_at TEXT NOT NULL,
                        success INTEGER NOT NULL,
                        latency_ms REAL,
                        method TEXT NOT NULL,
                        detail TEXT NOT NULL
                    )
                    """
                )
                self.connection.execute(
                    """
                    INSERT INTO main.samples_migrated
                    SELECT s.id, m.new_id, h.address, h.port, s.checked_at,
                           s.success, s.latency_ms, s.method, s.detail
                    FROM main.samples s
                    JOIN legacy_host_id_map m ON m.old_id = s.host_id
                    JOIN main.hosts h ON h.id = m.old_id
                    """
                )
                self.connection.execute("DROP TABLE main.samples")
                self.connection.execute(
                    "ALTER TABLE main.samples_migrated RENAME TO samples"
                )
                self.connection.execute("DROP TABLE main.hosts")
                self.connection.commit()
                self.connection.execute("PRAGMA foreign_keys = ON")
            else:
                self.connection.execute("DROP TABLE main.hosts")
        else:
            self.connection.execute("DROP TABLE main.hosts")
        self.connection.commit()

    def add_host(self, address: str, port: int) -> Host:
        cursor = self.connection.execute(
            "INSERT INTO config.hosts(address, port) VALUES (?, ?)",
            (address, port),
        )
        self.connection.commit()
        return Host(cursor.lastrowid, address, port)

    def add_hosts(self, addresses: list[str], port: int) -> tuple[list[Host], int]:
        unique_addresses = list(dict.fromkeys(addresses))
        if not unique_addresses:
            return [], 0
        with self.connection:
            placeholders = ",".join("?" for _ in unique_addresses)
            existing_addresses = {
                row["address"]
                for row in self.connection.execute(
                    f"SELECT address FROM config.hosts WHERE port = ? "
                    f"AND address IN ({placeholders})",
                    [port, *unique_addresses],
                )
            }
            cursor = self.connection.executemany(
                """
                INSERT INTO config.hosts(address, port) VALUES (?, ?)
                ON CONFLICT(address, port) DO NOTHING
                """,
                [(address, port) for address in unique_addresses],
            )
            added_count = cursor.rowcount
        hosts_by_address = {
            host.address: host
            for host in self.list_hosts()
            if host.port == port and host.address not in existing_addresses
        }
        added = [
            hosts_by_address[address]
            for address in unique_addresses
            if address in hosts_by_address
        ]
        return added, len(unique_addresses) - added_count

    def remove_host(self, host_id: int) -> None:
        with self.connection:
            self.connection.execute("DELETE FROM samples WHERE host_id = ?", (host_id,))
            self.connection.execute(
                "DELETE FROM config.hosts WHERE id = ?", (host_id,)
            )

    def list_hosts(self) -> list[Host]:
        rows = self.connection.execute(
            """
            SELECT id, address, port, enabled
            FROM config.hosts ORDER BY address, port
            """
        ).fetchall()
        return [
            Host(row["id"], row["address"], row["port"], bool(row["enabled"]))
            for row in rows
        ]

    def load_settings(self) -> dict[str, object] | None:
        row = self.connection.execute(
            "SELECT values_json FROM config.preferences WHERE id = 1"
        ).fetchone()
        if row is None:
            return None
        try:
            values = json.loads(row["values_json"])
        except json.JSONDecodeError as error:
            raise ValueError(f"Could not read settings from {self.settings_path}: {error}") from error
        if not isinstance(values, dict):
            raise ValueError("Stored settings must be a JSON object.")
        return values

    def save_settings(self, values: dict[str, object]) -> None:
        encoded = json.dumps(values)
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO config.preferences(id, values_json) VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET values_json = excluded.values_json
                """,
                (encoded,),
            )

    def record_sample(self, host: Host, result: ProbeResult) -> None:
        self.record_samples([(host, result)])

    def record_samples(self, samples: list[tuple[Host, ProbeResult]]) -> None:
        if not samples:
            return
        with self.connection:
            self.connection.executemany(
                """
                INSERT INTO samples(
                    host_id, address, port, checked_at, success, latency_ms, method, detail
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        host.id,
                        host.address,
                        host.port,
                        result.checked_at.isoformat(),
                        int(result.success),
                        result.latency_ms,
                        result.method,
                        result.detail,
                    )
                    for host, result in samples
                ],
            )

    def recent_samples(
        self, limit: int = 300, host_id: int | None = None
    ) -> list[Sample]:
        if limit < 1:
            raise ValueError("limit must be greater than zero")
        if host_id is None:
            rows = self.connection.execute(
                """
                SELECT * FROM samples
                ORDER BY checked_at DESC, id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM samples
                WHERE host_id = ?
                ORDER BY checked_at DESC, id DESC LIMIT ?
                """,
                (host_id, limit),
            ).fetchall()
        return [
            Sample(
                row["id"],
                row["host_id"],
                row["address"],
                row["port"],
                bool(row["success"]),
                row["latency_ms"],
                row["method"],
                row["detail"],
                datetime.fromisoformat(row["checked_at"]),
            )
            for row in rows
        ]

    def chart_samples(
        self,
        limit_per_host: int = 500,
        since: datetime | None = None,
        host_ids: set[int] | None = None,
    ) -> dict[int, list[Sample]]:
        if limit_per_host < 1:
            raise ValueError("limit_per_host must be greater than zero")
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        host_filter = ""
        parameters: list[object] = [since.isoformat()]
        if host_ids is not None:
            selected_ids = sorted(host_ids)
            if not selected_ids:
                return {}
            host_filter = (
                " AND s.host_id IN ("
                + ",".join("?" for _ in selected_ids)
                + ")"
            )
            parameters.extend(selected_ids)
        parameters.extend((limit_per_host, limit_per_host, limit_per_host))
        rows = self.connection.execute(
            f"""
            WITH ranked_samples AS (
                SELECT s.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY s.host_id
                           ORDER BY s.checked_at, s.id
                       ) AS sample_rank,
                       COUNT(*) OVER (PARTITION BY s.host_id) AS sample_count
                FROM samples s
                WHERE s.checked_at >= ?{host_filter}
            )
            SELECT * FROM ranked_samples
            WHERE sample_count <= ?
               OR (sample_rank - 1) % ((sample_count + ? - 1) / ?) = 0
               OR sample_rank = sample_count
            ORDER BY checked_at, id
            """,
            parameters,
        ).fetchall()
        samples_by_host: dict[int, list[Sample]] = {}
        for row in rows:
            sample = Sample(
                row["id"],
                row["host_id"],
                row["address"],
                row["port"],
                bool(row["success"]),
                row["latency_ms"],
                row["method"],
                row["detail"],
                datetime.fromisoformat(row["checked_at"]),
            )
            samples_by_host.setdefault(sample.host_id, []).append(sample)
        return samples_by_host

    def summaries(self, since: datetime | None = None) -> list[HostSummary]:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=1)
        rows = self.connection.execute(
            """
            SELECT h.address, h.port,
                   COUNT(s.id) AS samples,
                   COALESCE(SUM(s.success), 0) AS successes,
                   AVG(CASE WHEN s.success = 1 THEN s.latency_ms END) AS average_ms,
                   MIN(CASE WHEN s.success = 1 THEN s.latency_ms END) AS minimum_ms,
                   MAX(CASE WHEN s.success = 1 THEN s.latency_ms END) AS maximum_ms
            FROM config.hosts h
            LEFT JOIN samples s
                ON s.host_id = h.id AND s.checked_at >= ?
            GROUP BY h.id, h.address, h.port
            ORDER BY h.address, h.port
            """,
            (since.isoformat(),),
        ).fetchall()
        summaries = []
        for row in rows:
            samples = row["samples"]
            successes = row["successes"]
            loss_percent = 100.0 * (samples - successes) / samples if samples else 0.0
            summaries.append(
                HostSummary(
                    row["address"],
                    row["port"],
                    samples,
                    successes,
                    loss_percent,
                    row["average_ms"],
                    row["minimum_ms"],
                    row["maximum_ms"],
                )
            )
        return summaries

    def packet_loss(
        self, host_id: int, since: datetime | None = None
    ) -> float | None:
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(days=1)
        row = self.connection.execute(
            """
            SELECT COUNT(*) AS samples,
                   COALESCE(SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END), 0) AS failures
            FROM samples
            WHERE host_id = ? AND checked_at >= ?
            """,
            (host_id, since.isoformat()),
        ).fetchone()
        if row["samples"] == 0:
            return None
        return 100.0 * row["failures"] / row["samples"]

    def close(self) -> None:
        self.connection.close()
