import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import Host, HostSummary, ProbeResult, Sample


class MonitorDatabase:
    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            path = Path.home() / ".network-monitor" / "history.sqlite3"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(address, port)
            );
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
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

    def add_host(self, address: str, port: int) -> Host:
        cursor = self.connection.execute(
            "INSERT INTO hosts(address, port) VALUES (?, ?)", (address, port)
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
                    f"SELECT address FROM hosts WHERE port = ? "
                    f"AND address IN ({placeholders})",
                    [port, *unique_addresses],
                )
            }
            cursor = self.connection.executemany(
                """
                INSERT INTO hosts(address, port) VALUES (?, ?)
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
        self.connection.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        self.connection.commit()

    def list_hosts(self) -> list[Host]:
        rows = self.connection.execute(
            "SELECT id, address, port, enabled FROM hosts ORDER BY address, port"
        ).fetchall()
        return [
            Host(row["id"], row["address"], row["port"], bool(row["enabled"]))
            for row in rows
        ]

    def record_sample(self, host: Host, result: ProbeResult) -> None:
        self.connection.execute(
            """
            INSERT INTO samples(host_id, checked_at, success, latency_ms, method, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                host.id,
                result.checked_at.isoformat(),
                int(result.success),
                result.latency_ms,
                result.method,
                result.detail,
            ),
        )
        self.connection.commit()

    def recent_samples(
        self, limit: int = 300, host_id: int | None = None
    ) -> list[Sample]:
        if limit < 1:
            raise ValueError("limit must be greater than zero")
        if host_id is None:
            rows = self.connection.execute(
                """
                SELECT s.*, h.address, h.port
                FROM samples s JOIN hosts h ON h.id = s.host_id
                ORDER BY s.checked_at DESC, s.id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT s.*, h.address, h.port
                FROM samples s JOIN hosts h ON h.id = s.host_id
                WHERE s.host_id = ?
                ORDER BY s.checked_at DESC, s.id DESC LIMIT ?
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
        self, limit_per_host: int = 500, since: datetime | None = None
    ) -> dict[int, list[Sample]]:
        if limit_per_host < 1:
            raise ValueError("limit_per_host must be greater than zero")
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = self.connection.execute(
            """
            WITH ranked_samples AS (
                SELECT s.*, h.address, h.port,
                       ROW_NUMBER() OVER (
                           PARTITION BY s.host_id
                           ORDER BY s.checked_at, s.id
                       ) AS sample_rank,
                       COUNT(*) OVER (PARTITION BY s.host_id) AS sample_count
                FROM samples s
                JOIN hosts h ON h.id = s.host_id
                WHERE s.checked_at >= ?
            )
            SELECT * FROM ranked_samples
            WHERE sample_count <= ?
               OR (sample_rank - 1) % ((sample_count + ? - 1) / ?) = 0
               OR sample_rank = sample_count
            ORDER BY checked_at, id
            """,
            (since.isoformat(), limit_per_host, limit_per_host, limit_per_host),
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
            FROM hosts h
            LEFT JOIN samples s ON s.host_id = h.id AND s.checked_at >= ?
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
