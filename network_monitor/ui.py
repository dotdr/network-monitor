import ipaddress
import logging
import queue
import re
import threading
import tkinter as tk
import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, ttk

from .alerts import HostAlertTracker
from .models import Host, HostSummary, ProbeResult, Sample
from .notifications import notify
from .preferences import (
    Preferences,
    load_preferences,
    preferences_from_dict,
)
from .probes import probe_host
from .reporting import export_pdf
from .scanner import (
    MAX_SCAN_HOSTS,
    ScanResult,
    parse_scan_network,
    reverse_lookup,
    scan_network,
)
from .storage import MonitorDatabase

LOGGER = logging.getLogger(__name__)
DEFAULT_POLL_INTERVAL_SECONDS = 3
MIN_POLL_INTERVAL_SECONDS = 1
MAX_POLL_INTERVAL_SECONDS = 3600
DEFAULT_STATS_WINDOW_HOURS = 1
MIN_STATS_WINDOW_HOURS = 1
MAX_STATS_WINDOW_HOURS = 168
DEFAULT_GRAPH_WINDOW_HOURS = 24
MAX_GRAPH_WINDOW_HOURS = 720
DEFAULT_REPORT_WINDOW_HOURS = 24
MAX_REPORT_WINDOW_HOURS = 720
DEFAULT_ALERT_FAILURE_THRESHOLD = 2
MAX_ALERT_FAILURE_THRESHOLD = 20
CHART_COLORS = (
    "#2388c8",
    "#d36b38",
    "#398c68",
    "#8a63b8",
    "#c14f71",
    "#a08022",
    "#3f7d91",
    "#6c7741",
    "#596bb0",
    "#a6539a",
)


def validate_address(address: str) -> bool:
    import ipaddress

    value = address.strip()
    if not value or len(value) > 253 or any(char.isspace() for char in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        if value.endswith("."):
            value = value[:-1]
        labels = value.split(".")
        return all(
            label
            and len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        )


class MonitorApp:
    def __init__(self, root: tk.Tk, database: MonitorDatabase | None = None) -> None:
        self.root = root
        self.database = database or MonitorDatabase()
        self.preferences_path = self.database.path.parent / "settings.json"
        settings = self.database.load_settings()
        if settings is None:
            self.preferences = (
                load_preferences(self.preferences_path)
                if self.preferences_path.exists()
                else Preferences()
            )
            self.database.save_settings(asdict(self.preferences))
        else:
            self.preferences = preferences_from_dict(settings)
        self.messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event: threading.Event | None = None
        self.worker: threading.Thread | None = None
        self.hosts: list[Host] = self.database.list_hosts()
        self.selected_host_id: int | None = None
        self.hostnames: dict[int, str] = {}
        self.hostname_lookups: set[int] = set()
        self.chart_samples_by_host: dict[int, list[Sample]] = {}
        self.last_chart_refresh = 0.0
        self.graph_host_ids: set[int] | None = (
            set(self.preferences.graph_host_ids)
            if self.preferences.graph_host_ids is not None
            else None
        )
        self.known_host_ids: set[int] = {host.id for host in self.hosts}
        self.stats_window_hours = self.preferences.stats_window_hours
        self.graph_window_hours = self.preferences.graph_window_hours
        self.report_window_hours = self.preferences.report_window_hours
        self.poll_interval_seconds = self.preferences.poll_interval_seconds
        self.alerts_enabled = self.preferences.alerts_enabled
        self.alert_failure_threshold = self.preferences.alert_failure_threshold
        self.alert_tracker = HostAlertTracker(self.alert_failure_threshold)
        self.scan_results: dict[str, ScanResult] = {}
        self.scan_window: tk.Toplevel | None = None
        self.scan_tree: ttk.Treeview | None = None
        self.scan_button: ttk.Button | None = None
        self.scan_status: ttk.Label | None = None
        self.run_started_at: datetime | None = None
        self.run_started_monotonic: float | None = None
        self.run_duration_seconds: float | None = None
        self._configure_window()
        self._build_ui()
        self._refresh_hosts()
        self._refresh_history()
        self.root.after(150, self._drain_messages)
        self.root.after(1000, self._refresh_run_metadata)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_window(self) -> None:
        self.root.title("Network Monitor")
        self.root.geometry("1180x760")
        self.root.minsize(1120, 620)
        self.root.configure(bg="#f4f7fb")
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#f4f7fb")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f4f7fb", foreground="#172b3d")
        style.configure("Card.TLabel", background="#ffffff", foreground="#172b3d")
        style.configure(
            "Title.TLabel", font=("Segoe UI", 19, "bold"), foreground="#18324b"
        )
        style.configure(
            "Subtle.TLabel", font=("Segoe UI", 9), foreground="#64788b"
        )
        style.configure(
            "Metric.TLabel", font=("Segoe UI", 21, "bold"), foreground="#18324b"
        )
        style.configure("Treeview", rowheight=27, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure(
            "Accent.TButton",
            background="#1769aa",
            foreground="#ffffff",
            padding=(12, 7),
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#12588f"), ("disabled", "#91abc1")],
        )
        style.configure("TButton", padding=(8, 6))

    def _build_ui(self) -> None:
        header = ttk.Frame(self.root, padding=(22, 16, 22, 10))
        header.pack(fill="x")
        ttk.Label(header, text="Network Monitor", style="Title.TLabel").pack(
            side="left"
        )
        self.status_label = ttk.Label(
            header, text="●  Stopped", foreground="#64788b", font=("Segoe UI", 10)
        )
        self.status_label.pack(side="right", padx=(0, 12))
        self.run_metadata_label = ttk.Label(
            header,
            text="",
            foreground="#64788b",
            font=("Segoe UI", 9),
        )
        self.run_metadata_label.pack(side="right", padx=(0, 12))
        ttk.Button(header, text="Reports", command=self._show_report).pack(side="right")
        self.scan_main_button = ttk.Button(
            header, text="Scan LAN", command=self._open_scanner
        )
        self.scan_main_button.pack(side="right", padx=(0, 8))

        body = ttk.Frame(self.root, padding=(18, 8, 18, 18))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=0, minsize=430)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(body, style="Card.TFrame", padding=16)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        ttk.Label(
            sidebar, text="MONITORED HOSTS", style="Subtle.TLabel"
        ).pack(anchor="w", pady=(0, 10))
        form = ttk.Frame(sidebar, style="Card.TFrame")
        form.pack(fill="x")
        self.address_entry = ttk.Entry(form)
        self.address_entry.pack(fill="x", pady=(0, 8))
        self.address_entry.insert(0, "example.com or 192.168.1.1")
        self.address_entry.bind("<FocusIn>", self._clear_placeholder)
        port_row = ttk.Frame(form, style="Card.TFrame")
        port_row.pack(fill="x")
        ttk.Label(port_row, text="TCP port", style="Card.TLabel").pack(side="left")
        self.port_entry = ttk.Entry(port_row, width=8)
        self.port_entry.insert(0, "443")
        self.port_entry.pack(side="left", padx=(8, 0))
        ttk.Button(
            port_row, text="Reverse DNS", command=self._lookup_entered_address
        ).pack(side="right", padx=(6, 0))
        self.add_button = ttk.Button(
            port_row, text="Add host", style="Accent.TButton", command=self._add_host
        )
        self.add_button.pack(side="right")
        self.lookup_result = ttk.Label(
            form, text="Enter an IP address to look up its hostname.",
            style="Subtle.TLabel", wraplength=245
        )
        self.lookup_result.pack(anchor="w", pady=(5, 0))

        host_frame = ttk.Frame(sidebar, style="Card.TFrame")
        host_frame.pack(fill="both", expand=True, pady=(16, 10))
        host_frame.rowconfigure(0, weight=1)
        host_frame.columnconfigure(0, weight=1)
        self.host_list = ttk.Treeview(
            host_frame,
            columns=("hostname", "address", "latency", "loss"),
            show="headings",
            selectmode="browse",
            height=12,
        )
        for column, title, width in (
            ("hostname", "Hostname", 105),
            ("address", "IP / Address", 85),
            ("latency", "Min / Avg / Max", 150),
            ("loss", "Loss %", 55),
        ):
            self.host_list.heading(column, text=title)
            self.host_list.column(column, width=width, minwidth=45, anchor="w")
        self.host_list.grid(row=0, column=0, sticky="nsew")
        host_scrollbar = ttk.Scrollbar(
            host_frame, orient="vertical", command=self.host_list.yview
        )
        host_scrollbar.grid(row=0, column=1, sticky="ns")
        self.host_list.configure(yscrollcommand=host_scrollbar.set)
        self.host_list.bind("<<TreeviewSelect>>", self._select_host)
        stats_window_row = ttk.Frame(sidebar, style="Card.TFrame")
        stats_window_row.pack(fill="x", pady=(0, 10))
        ttk.Label(
            stats_window_row, text="Stats window (hours)", style="Card.TLabel"
        ).pack(side="left")
        self.stats_window_var = tk.StringVar(value=str(self.stats_window_hours))
        self.stats_window_var.trace_add("write", self._stats_window_changed)
        self.stats_window_entry = ttk.Spinbox(
            stats_window_row,
            from_=MIN_STATS_WINDOW_HOURS,
            to=MAX_STATS_WINDOW_HOURS,
            increment=1,
            textvariable=self.stats_window_var,
            width=7,
        )
        self.stats_window_entry.pack(side="right")
        controls = ttk.Frame(sidebar, style="Card.TFrame")
        controls.pack(fill="x")
        self.start_button = ttk.Button(
            controls, text="Start monitoring", style="Accent.TButton", command=self._start
        )
        self.start_button.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.stop_button = ttk.Button(
            controls, text="Stop", command=self._stop, state="disabled"
        )
        self.stop_button.pack(side="left", fill="x", expand=True, padx=(5, 0))
        interval_row = ttk.Frame(sidebar, style="Card.TFrame")
        interval_row.pack(fill="x", pady=(12, 0))
        ttk.Label(
            interval_row, text="Poll every (seconds)", style="Card.TLabel"
        ).pack(side="left")
        self.poll_interval_var = tk.StringVar(
            value=str(self.poll_interval_seconds)
        )
        self.poll_interval_var.trace_add("write", self._poll_interval_changed)
        self.poll_interval_entry = ttk.Spinbox(
            interval_row,
            from_=MIN_POLL_INTERVAL_SECONDS,
            to=MAX_POLL_INTERVAL_SECONDS,
            increment=1,
            textvariable=self.poll_interval_var,
            width=7,
        )
        self.poll_interval_entry.pack(side="right")
        self.remove_button = ttk.Button(
            sidebar,
            text="Remove selected host",
            command=self._remove_host,
        )
        self.remove_button.pack(fill="x", pady=(9, 0))
        self.alerts_enabled_var = tk.BooleanVar(value=self.alerts_enabled)
        ttk.Checkbutton(
            sidebar,
            text="Notify on host down / recovery",
            variable=self.alerts_enabled_var,
        ).pack(anchor="w", pady=(10, 0))
        threshold_row = ttk.Frame(sidebar, style="Card.TFrame")
        threshold_row.pack(fill="x", pady=(5, 0))
        ttk.Label(
            threshold_row, text="Alert after failures", style="Card.TLabel"
        ).pack(side="left")
        self.alert_threshold_var = tk.StringVar(
            value=str(self.alert_failure_threshold)
        )
        self.alert_threshold_var.trace_add("write", self._alert_threshold_changed)
        self.alert_threshold_entry = ttk.Spinbox(
            threshold_row,
            from_=1,
            to=MAX_ALERT_FAILURE_THRESHOLD,
            textvariable=self.alert_threshold_var,
            width=7,
        )
        self.alert_threshold_entry.pack(side="right")
        ttk.Label(
            sidebar,
            text="Monitor checks use ICMP, then TCP fallback. Polling can be set from 1 to 3600 seconds.",
            style="Subtle.TLabel",
            wraplength=245,
        ).pack(anchor="w", pady=(13, 0))

        main = ttk.Frame(body)
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)
        self.metric_values: dict[str, ttk.Label] = {}
        self.metric_titles: dict[str, ttk.Label] = {}
        metrics = ttk.Frame(main)
        metrics.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        for column, (key, title) in enumerate(
            [
                ("status", "CURRENT STATUS"),
                ("latency", "LATEST LATENCY"),
                ("loss", f"{self.stats_window_hours}H PACKET LOSS"),
            ]
        ):
            metrics.columnconfigure(column, weight=1)
            card = ttk.Frame(metrics, style="Card.TFrame", padding=(15, 11))
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
            metric_title = ttk.Label(card, text=title, style="Subtle.TLabel")
            metric_title.pack(anchor="w")
            self.metric_titles[key] = metric_title
            value = ttk.Label(card, text="—", style="Metric.TLabel")
            value.pack(anchor="w", pady=(4, 0))
            self.metric_values[key] = value

        content = ttk.Frame(main, style="Card.TFrame", padding=14)
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(1, weight=2)
        content.rowconfigure(3, weight=1)
        chart_header = ttk.Frame(content, style="Card.TFrame")
        chart_header.grid(row=0, column=0, sticky="ew")
        self.chart_title = ttk.Label(
            chart_header, text="Latency · selected hosts", style="Card.TLabel",
            font=("Segoe UI", 11, "bold")
        )
        self.chart_title.pack(side="left")
        ttk.Button(
            chart_header,
            text="Choose hosts",
            command=self._open_graph_host_selector,
        ).pack(side="right", padx=(8, 0))
        graph_range = ttk.Frame(chart_header, style="Card.TFrame")
        graph_range.pack(side="right", padx=(0, 8))
        ttk.Label(graph_range, text="Range h", style="Card.TLabel").pack(side="left")
        self.graph_window_var = tk.StringVar(
            value=str(self.graph_window_hours)
        )
        self.graph_window_var.trace_add("write", self._graph_window_changed)
        self.graph_window_entry = ttk.Spinbox(
            graph_range,
            from_=1,
            to=MAX_GRAPH_WINDOW_HOURS,
            increment=1,
            textvariable=self.graph_window_var,
            width=5,
        )
        self.graph_window_entry.pack(side="left", padx=(5, 0))
        ttk.Label(
            chart_header, text="Color = host · × = failed check", style="Subtle.TLabel"
        ).pack(side="right")
        self.chart = tk.Canvas(
            content,
            height=245,
            bg="#ffffff",
            highlightthickness=0,
            relief="flat",
        )
        self.chart.grid(row=1, column=0, sticky="nsew", pady=(7, 14))
        self.chart.bind("<Configure>", lambda _event: self._draw_chart())
        history_header = ttk.Frame(content, style="Card.TFrame")
        history_header.grid(row=2, column=0, sticky="ew", pady=(0, 7))
        ttk.Label(
            history_header, text="Recent history", style="Card.TLabel",
            font=("Segoe UI", 11, "bold")
        ).pack(side="left")
        self.history_note = ttk.Label(
            history_header, text="Last 200 checks", style="Subtle.TLabel"
        )
        self.history_note.pack(side="right")
        table_frame = ttk.Frame(content, style="Card.TFrame")
        table_frame.grid(row=3, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        columns = ("time", "host", "result", "latency", "method")
        self.history = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=8
        )
        for column, title, width in [
            ("time", "Time", 145),
            ("host", "Host", 190),
            ("result", "Result", 90),
            ("latency", "Latency", 95),
            ("method", "Method", 110),
        ]:
            self.history.heading(column, text=title)
            self.history.column(column, width=width, anchor="w")
        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.history.yview
        )
        self.history.configure(yscrollcommand=scrollbar.set)
        self.history.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.history.tag_configure("failed", foreground="#b44343")
        self.history.tag_configure("success", foreground="#237a58")

    @staticmethod
    def _clear_placeholder(event: tk.Event) -> None:
        entry = event.widget
        if entry.get() == "example.com or 192.168.1.1":
            entry.delete(0, "end")

    def _poll_interval_changed(self, *_args: str) -> None:
        try:
            seconds = int(self.poll_interval_var.get())
        except ValueError:
            return
        if MIN_POLL_INTERVAL_SECONDS <= seconds <= MAX_POLL_INTERVAL_SECONDS:
            self.poll_interval_seconds = seconds

    def _poll_interval(self) -> int | None:
        try:
            seconds = int(self.poll_interval_var.get())
        except ValueError:
            return None
        if MIN_POLL_INTERVAL_SECONDS <= seconds <= MAX_POLL_INTERVAL_SECONDS:
            return seconds
        return None

    def _graph_window_changed(self, *_args: str) -> None:
        try:
            hours = int(self.graph_window_var.get())
        except ValueError:
            return
        if not 1 <= hours <= MAX_GRAPH_WINDOW_HOURS:
            return
        self.graph_window_hours = hours
        self._refresh_chart_samples()

    def _alert_threshold_changed(self, *_args: str) -> None:
        try:
            threshold = int(self.alert_threshold_var.get())
        except ValueError:
            return
        if 1 <= threshold <= MAX_ALERT_FAILURE_THRESHOLD:
            self.alert_failure_threshold = threshold
            self.alert_tracker.failure_threshold = threshold

    def _refresh_chart_samples(self) -> None:
        since = datetime.now(timezone.utc) - timedelta(
            hours=self.graph_window_hours
        )
        self.chart_samples_by_host = self.database.chart_samples(
            since=since, host_ids=self.graph_host_ids
        )
        self.last_chart_refresh = time.monotonic()
        self._draw_chart()

    def _lookup_entered_address(self) -> None:
        value = self.address_entry.get().strip()
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            messagebox.showerror(
                "Reverse DNS",
                "Enter a valid IP address to look up its hostname.",
            )
            return
        self.lookup_result.configure(text=f"Looking up {address}…")
        threading.Thread(
            target=self._reverse_lookup_worker,
            args=(address, "entered"),
            name="reverse-dns",
            daemon=True,
        ).start()

    def _reverse_lookup_worker(self, address: str, source: str) -> None:
        try:
            hostname = reverse_lookup(address)
        except (OSError, ValueError) as error:
            self.messages.put(("reverse_lookup_error", (address, source, str(error))))
        else:
            self.messages.put(("reverse_lookup", (address, source, hostname)))

    def _open_scanner(self) -> None:
        if self.scan_window is not None and self.scan_window.winfo_exists():
            self.scan_window.lift()
            return
        window = tk.Toplevel(self.root)
        self.scan_window = window
        window.title("Private network scanner")
        window.geometry("720x490")
        window.minsize(580, 380)
        window.transient(self.root)
        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Scan a private LAN", style="Title.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            frame,
            text=f"ICMP discovery only · RFC 1918 IPv4 · max {MAX_SCAN_HOSTS} addresses",
            style="Subtle.TLabel",
        ).pack(anchor="w", pady=(3, 12))
        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=(0, 10))
        ttk.Label(controls, text="Network (CIDR)").pack(side="left")
        self.scan_network_entry = ttk.Entry(controls)
        self.scan_network_entry.pack(side="left", fill="x", expand=True, padx=8)
        self.scan_network_entry.insert(0, "192.168.1.0/24")
        self.scan_button = ttk.Button(
            controls,
            text="Start scan",
            style="Accent.TButton",
            command=self._start_scan,
        )
        self.scan_button.pack(side="right")
        self.scan_status = ttk.Label(
            frame, text="Only responsive hosts are listed.", style="Subtle.TLabel"
        )
        self.scan_status.pack(anchor="w", pady=(0, 7))
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill="both", expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        self.scan_tree = ttk.Treeview(
            tree_frame,
            columns=("address", "latency", "hostname"),
            show="headings",
            selectmode="extended",
        )
        for column, title, width in (
            ("address", "IP address", 190),
            ("latency", "ICMP latency", 130),
            ("hostname", "Hostname (PTR)", 270),
        ):
            self.scan_tree.heading(column, text=title)
            self.scan_tree.column(column, width=width, anchor="w")
        self.scan_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.scan_tree.yview
        )
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            actions,
            text="Look up selected hostname",
            command=self._lookup_scanned_address,
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Add selected hosts",
            style="Accent.TButton",
            command=self._add_scanned_hosts,
        ).pack(side="right")
        window.protocol("WM_DELETE_WINDOW", self._close_scanner)

    def _close_scanner(self) -> None:
        if self.scan_window is not None:
            self.scan_window.destroy()
        self.scan_window = None
        self.scan_tree = None
        self.scan_button = None
        self.scan_status = None

    def _start_scan(self) -> None:
        if self.scan_button is None or self.scan_status is None:
            return
        value = self.scan_network_entry.get()
        try:
            network = parse_scan_network(value)
        except ValueError as error:
            messagebox.showerror("Invalid scan network", str(error))
            return
        self.scan_results.clear()
        if self.scan_tree:
            for item in self.scan_tree.get_children():
                self.scan_tree.delete(item)
        self.scan_button.configure(state="disabled")
        self.scan_status.configure(text=f"Scanning {network} with ICMP…")
        threading.Thread(
            target=self._scan_worker,
            args=(str(network),),
            name="private-network-scan",
            daemon=True,
        ).start()

    def _scan_worker(self, network: str) -> None:
        try:
            results = scan_network(network)
        except Exception as error:
            LOGGER.exception("Private network scan failed")
            self.messages.put(("scan_error", str(error)))
        else:
            self.messages.put(("scan_complete", results))

    def _lookup_scanned_address(self) -> None:
        if self.scan_tree is None:
            return
        selection = self.scan_tree.selection()
        if not selection:
            return
        address = self.scan_tree.item(selection[0], "values")[0]
        self.scan_status.configure(text=f"Looking up {address}…")
        threading.Thread(
            target=self._reverse_lookup_worker,
            args=(address, "scan"),
            name="scan-reverse-dns",
            daemon=True,
        ).start()

    def _add_scanned_hosts(self) -> None:
        if self.scan_tree is None:
            return
        selection = self.scan_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Select hosts", "Select one or more discovered hosts first."
            )
            return
        addresses = [
            self.scan_tree.item(item, "values")[0] for item in selection
        ]
        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid port", "Enter a TCP port from 1 to 65535 before adding hosts."
            )
            return
        except Exception as error:
            LOGGER.exception("Could not add discovered host")
            messagebox.showerror("Could not add host", str(error))
            return
        try:
            added, skipped = self.database.add_hosts(addresses, port)
        except Exception as error:
            LOGGER.exception("Could not add discovered hosts")
            messagebox.showerror("Could not add hosts", str(error))
            return
        if added:
            self.selected_host_id = added[-1].id
        self._refresh_hosts()
        messagebox.showinfo(
            "Hosts added",
            f"Added {len(added)} host(s) on TCP port {port}."
            + (f"\nSkipped {skipped} already monitored host(s)." if skipped else ""),
        )

    def _refresh_hosts(self) -> None:
        self.hosts = self.database.list_hosts()
        self.host_list.heading(
            "latency", text=f"Min / Avg / Max ({self.stats_window_hours}h)"
        )
        current_ids = {host.id for host in self.hosts}
        if self.graph_host_ids is None:
            self.graph_host_ids = set(current_ids)
        else:
            added_ids = current_ids - self.known_host_ids
            self.graph_host_ids.intersection_update(current_ids)
            self.graph_host_ids.update(added_ids)
        self.known_host_ids = current_ids
        statistics = self._host_statistics()
        for item in self.host_list.get_children():
            self.host_list.delete(item)
        self.hostnames = {
            host_id: hostname
            for host_id, hostname in self.hostnames.items()
            if host_id in current_ids
        }
        self.hostname_lookups.intersection_update(current_ids)
        for host in self.hosts:
            summary = statistics[(host.address, host.port)]
            self.host_list.insert(
                "",
                "end",
                iid=str(host.id),
                values=(
                    self.hostnames.get(host.id, host.address),
                    host.address,
                    self._format_latency_range(summary),
                    f"{summary.loss_percent:.1f}%"
                    if summary.samples
                    else "—",
                ),
            )
            self._schedule_hostname_lookup(host)
        if self.selected_host_id is not None:
            item_id = str(self.selected_host_id)
            if self.host_list.exists(item_id):
                self.host_list.selection_set(item_id)
            else:
                self.selected_host_id = None
        if self.selected_host_id is None and self.hosts:
            self.host_list.selection_set(str(self.hosts[0].id))
            self.selected_host_id = self.hosts[0].id
        self._refresh_history()

    def _host_statistics(self) -> dict[tuple[str, int], HostSummary]:
        since = datetime.now(timezone.utc) - timedelta(hours=self.stats_window_hours)
        return {
            (summary.address, summary.port): summary
            for summary in self.database.summaries(since)
        }

    def _refresh_host_statistics(self) -> None:
        self.host_list.heading(
            "latency", text=f"Min / Avg / Max ({self.stats_window_hours}h)"
        )
        statistics = self._host_statistics()
        for host in self.hosts:
            item_id = str(host.id)
            if not self.host_list.exists(item_id):
                continue
            summary = statistics[(host.address, host.port)]
            values = list(self.host_list.item(item_id, "values"))
            values[2] = self._format_latency_range(summary)
            values[3] = f"{summary.loss_percent:.1f}%" if summary.samples else "—"
            self.host_list.item(item_id, values=values)

    def _stats_window_changed(self, *_args: str) -> None:
        try:
            hours = int(self.stats_window_var.get())
        except ValueError:
            return
        if not MIN_STATS_WINDOW_HOURS <= hours <= MAX_STATS_WINDOW_HOURS:
            return
        self.stats_window_hours = hours
        self._refresh_host_statistics()
        self.metric_titles["loss"].configure(
            text=f"{self.stats_window_hours}H PACKET LOSS"
        )
        self._update_metrics(
            self.database.recent_samples(
                limit=200, host_id=self.selected_host_id
            )
        )

    def _open_graph_host_selector(self) -> None:
        if not self.hosts:
            messagebox.showinfo("No hosts", "Add hosts before selecting graph series.")
            return
        window = tk.Toplevel(self.root)
        window.title("Choose graph hosts")
        window.geometry("390x460")
        window.minsize(320, 260)
        window.transient(self.root)
        window.grab_set()
        frame = ttk.Frame(window, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(
            frame, text="Hosts shown on the graph", style="Title.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text="Select the hosts whose latency series should be displayed.",
            style="Subtle.TLabel",
        ).pack(anchor="w", pady=(3, 10))
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        canvas = tk.Canvas(list_frame, highlightthickness=0, bg="#f4f7fb")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind(
            "<Configure>",
            lambda _event: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        variables: dict[int, tk.BooleanVar] = {}
        for host in self.hosts:
            variable = tk.BooleanVar(
                value=host.id in (self.graph_host_ids or set())
            )
            variables[host.id] = variable
            hostname = self.hostnames.get(host.id, host.address)
            ttk.Checkbutton(
                inner,
                text=f"{hostname}  ({host.address})",
                variable=variable,
            ).pack(anchor="w", fill="x", pady=3)

        def set_all(selected: bool) -> None:
            for variable in variables.values():
                variable.set(selected)

        def apply_selection() -> None:
            self.graph_host_ids = {
                host_id for host_id, variable in variables.items() if variable.get()
            }
            self._draw_chart()
            window.destroy()

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(
            actions, text="Select all", command=lambda: set_all(True)
        ).pack(side="left")
        ttk.Button(
            actions, text="Clear", command=lambda: set_all(False)
        ).pack(side="left", padx=(6, 0))
        ttk.Button(
            actions,
            text="Apply",
            style="Accent.TButton",
            command=apply_selection,
        ).pack(side="right")

    def _schedule_hostname_lookup(self, host: Host) -> None:
        if host.id in self.hostname_lookups:
            return
        try:
            address = ipaddress.ip_address(host.address)
        except ValueError:
            return
        self.hostname_lookups.add(host.id)
        threading.Thread(
            target=self._host_hostname_worker,
            args=(host.id, host.address),
            name=f"host-reverse-dns-{host.id}",
            daemon=True,
        ).start()

    def _host_hostname_worker(self, host_id: int, address: str) -> None:
        try:
            hostname = reverse_lookup(address)
        except (OSError, ValueError):
            return
        self.messages.put(("host_hostname", (host_id, hostname)))

    def _add_host(self) -> None:
        address = self.address_entry.get().strip()
        try:
            port = int(self.port_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid port", "Enter a TCP port from 1 to 65535.")
            return
        if not validate_address(address):
            messagebox.showerror(
                "Invalid host",
                "Enter a valid IP address or hostname (without a URL scheme or path).",
            )
            return
        if not 1 <= port <= 65535:
            messagebox.showerror("Invalid port", "Enter a TCP port from 1 to 65535.")
            return
        try:
            host = self.database.add_host(address, port)
        except Exception as error:
            LOGGER.exception("Could not add host")
            messagebox.showerror("Could not add host", str(error))
            return
        self.selected_host_id = host.id
        self.address_entry.delete(0, "end")
        self._refresh_hosts()

    def _remove_host(self) -> None:
        selection = self.host_list.selection()
        if not selection:
            return
        host_id = int(selection[0])
        host = next(host for host in self.hosts if host.id == host_id)
        if not messagebox.askyesno(
            "Remove host",
            f"Remove {host.address}:{host.port} and its saved history?",
        ):
            return
        self.database.remove_host(host.id)
        self.selected_host_id = None
        self._refresh_hosts()

    def _select_host(self, _event: tk.Event | None = None) -> None:
        selection = self.host_list.selection()
        if selection:
            self.selected_host_id = int(selection[0])
            self._refresh_history()

    def _start(self) -> None:
        if not self.hosts:
            messagebox.showinfo("Add a host", "Add at least one host before monitoring.")
            return
        if self.worker and self.worker.is_alive():
            return
        interval = self._poll_interval()
        if interval is None:
            messagebox.showerror(
                "Invalid polling interval",
                f"Enter a whole number from {MIN_POLL_INTERVAL_SECONDS} to "
                f"{MAX_POLL_INTERVAL_SECONDS} seconds.",
            )
            return
        self.poll_interval_seconds = interval
        self.run_started_at = datetime.now().astimezone()
        self.run_started_monotonic = time.monotonic()
        self.run_duration_seconds = None
        self.run_metadata_label.configure(
            text=f"Started {self.run_started_at.strftime('%Y-%m-%d %H:%M:%S')} · Running 00:00:00"
        )
        self.stop_event = threading.Event()
        self.worker = threading.Thread(
            target=self._monitor_loop,
            args=(tuple(self.hosts), self.stop_event),
            name="network-monitor",
            daemon=True,
        )
        self.worker.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.add_button.configure(state="disabled")
        self.remove_button.configure(state="disabled")
        self.address_entry.configure(state="disabled")
        self.port_entry.configure(state="disabled")
        self.scan_main_button.configure(state="disabled")
        self.status_label.configure(text="●  Monitoring", foreground="#237a58")

    def _stop(self) -> None:
        if self.stop_event:
            self.stop_event.set()
        self.status_label.configure(text="●  Stopping…", foreground="#a76b14")
        self.stop_button.configure(state="disabled")

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total_seconds = max(0, int(seconds))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def _refresh_run_metadata(self) -> None:
        if (
            self.run_started_at is not None
            and self.run_started_monotonic is not None
            and self.worker is not None
            and self.worker.is_alive()
        ):
            elapsed = max(0.0, time.monotonic() - self.run_started_monotonic)
            self.run_metadata_label.configure(
                text=(
                    f"Started {self.run_started_at.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"· Running {self._format_duration(elapsed)}"
                )
            )
        self.root.after(1000, self._refresh_run_metadata)

    def _monitor_loop(
        self, hosts: tuple[Host, ...], stop_event: threading.Event
    ) -> None:
        while not stop_event.is_set():
            cycle_started = time.monotonic()
            for host in hosts:
                if stop_event.is_set():
                    break
                try:
                    result = probe_host(host)
                    self.messages.put(("sample", (host, result)))
                except Exception as error:
                    LOGGER.exception("Unexpected probe error for %s", host.address)
                    result = ProbeResult(
                        False,
                        None,
                        "Error",
                        str(error),
                        datetime.now(timezone.utc),
                    )
                    self.messages.put(("sample", (host, result)))
            elapsed = time.monotonic() - cycle_started
            stop_event.wait(max(0.1, self.poll_interval_seconds - elapsed))
        self.messages.put(("stopped", None))

    def _drain_messages(self) -> None:
        pending_samples: list[tuple[Host, ProbeResult]] = []
        processed = 0
        max_messages = 500
        while processed < max_messages:
            try:
                kind, payload = self.messages.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if kind == "sample":
                pending_samples.append(payload)
            elif kind == "stopped":
                if self.run_started_monotonic is not None:
                    self.run_duration_seconds = max(
                        0.0, time.monotonic() - self.run_started_monotonic
                    )
                if self.run_started_at is not None:
                    duration = self._format_duration(self.run_duration_seconds or 0.0)
                    self.run_metadata_label.configure(
                        text=(
                            f"Started {self.run_started_at.strftime('%Y-%m-%d %H:%M:%S')} "
                            f"· Duration {duration}"
                        )
                    )
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.add_button.configure(state="normal")
                self.remove_button.configure(state="normal")
                self.address_entry.configure(state="normal")
                self.port_entry.configure(state="normal")
                self.scan_main_button.configure(state="normal")
                self.status_label.configure(
                    text="●  Stopped", foreground="#64788b"
                )
            elif kind == "scan_complete":
                results = payload
                if self.scan_button is not None:
                    self.scan_button.configure(state="normal")
                if self.scan_tree is not None:
                    self.scan_results = {
                        result.address: result for result in results
                    }
                    for result in results:
                        self.scan_tree.insert(
                            "",
                            "end",
                            values=(
                                result.address,
                                f"{result.latency_ms:.2f} ms",
                                "",
                            ),
                        )
                if self.scan_status is not None:
                    self.scan_status.configure(
                        text=f"Found {len(results)} ICMP-responsive host(s)."
                    )
            elif kind == "scan_error":
                if self.scan_button is not None:
                    self.scan_button.configure(state="normal")
                if self.scan_status is not None:
                    self.scan_status.configure(text="Scan failed.")
                messagebox.showerror("Network scan failed", str(payload))
            elif kind == "reverse_lookup":
                address, source, hostname = payload
                if source == "entered":
                    self.lookup_result.configure(text=f"{address} → {hostname}")
                elif self.scan_tree is not None and self.scan_status is not None:
                    selection = self.scan_tree.selection()
                    if selection and self.scan_tree.item(selection[0], "values")[0] == address:
                        self.scan_tree.set(selection[0], "hostname", hostname)
                    self.scan_status.configure(text=f"{address} → {hostname}")
            elif kind == "reverse_lookup_error":
                address, source, detail = payload
                if source == "entered":
                    self.lookup_result.configure(
                        text=f"No hostname found for {address}."
                    )
                elif self.scan_status is not None:
                    self.scan_status.configure(
                        text=f"No PTR record for {address} ({detail})."
                    )
            elif kind == "host_hostname":
                host_id, hostname = payload
                if any(host.id == host_id for host in self.hosts):
                    self.hostnames[host_id] = hostname
                    item_id = str(host_id)
                    if self.host_list.exists(item_id):
                        values = list(self.host_list.item(item_id, "values"))
                        values[0] = hostname
                        self.host_list.item(item_id, values=values)
                        self._draw_chart()

        if pending_samples:
            try:
                self.database.record_samples(pending_samples)
            except Exception:
                LOGGER.exception("Could not save monitor samples")
                self.status_label.configure(
                    text="●  Storage error", foreground="#b44343"
                )
            else:
                for host, result in pending_samples:
                    self._handle_alert(host, result)
                self._refresh_host_statistics()
                self._refresh_history(refresh_chart=False)
                if time.monotonic() - self.last_chart_refresh >= 15:
                    self._refresh_chart_samples()
        self.root.after(25 if processed == max_messages else 150, self._drain_messages)

    def _refresh_history(self, refresh_chart: bool = True) -> None:
        for item in self.history.get_children():
            self.history.delete(item)
        samples = self.database.recent_samples(
            limit=200, host_id=self.selected_host_id
        )
        for sample in samples:
            self.history.insert(
                "",
                "end",
                values=(
                    sample.checked_at.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                    sample.address,
                    "Success" if sample.success else "Failed",
                    f"{sample.latency_ms:.2f} ms"
                    if sample.latency_ms is not None
                    else "—",
                    sample.method,
                ),
                tags=("success" if sample.success else "failed",),
            )
        self._update_metrics(samples)
        if refresh_chart:
            self._refresh_chart_samples()

    def _handle_alert(self, host: Host, result: ProbeResult) -> None:
        transition = self.alert_tracker.record(host.id, result.success)
        if not transition or not self.alerts_enabled_var.get():
            return
        if transition == "offline":
            self._send_host_alert(
                f"{host.address} is offline",
                f"No response after {self.alert_failure_threshold} consecutive checks.",
            )
        else:
            self._send_host_alert(
                f"{host.address} is back online",
                f"Successful {result.method} check.",
            )

    def _send_host_alert(self, title: str, message: str) -> None:
        try:
            notify(title, message)
        except RuntimeError as error:
            LOGGER.error("%s", error)
            self.status_label.configure(
                text="●  Notification unavailable", foreground="#b44343"
            )
        else:
            self.status_label.configure(
                text=f"●  {title}", foreground="#b44343"
            )

    def _update_metrics(self, samples: list[Sample]) -> None:
        latest = samples[0] if samples else None
        self.metric_values["status"].configure(
            text=("Online" if latest and latest.success else "Offline")
            if latest
            else "—",
            foreground=(
                "#237a58" if latest and latest.success else "#b44343"
            )
            if latest
            else "#18324b",
        )
        self.metric_values["latency"].configure(
            text=f"{latest.latency_ms:.1f} ms"
            if latest and latest.latency_ms is not None
            else "—"
        )
        loss = (
            self.database.packet_loss(
                self.selected_host_id,
                datetime.now(timezone.utc)
                - timedelta(hours=self.stats_window_hours),
            )
            if self.selected_host_id is not None
            else None
        )
        self.metric_values["loss"].configure(
            text=f"{loss:.1f}%" if loss is not None else "—"
        )

    def _draw_chart(self) -> None:
        canvas = self.chart
        canvas.delete("all")
        width = max(canvas.winfo_width(), 200)
        height = max(canvas.winfo_height(), 150)
        host_series = self._selected_chart_series()
        self.chart_title.configure(
            text=(
                f"Latency · {len(host_series)} host(s) · {self.graph_window_hours}h"
                if host_series
                else (
                    f"Latency · no hosts selected · {self.graph_window_hours}h"
                    if self.hosts and not self.graph_host_ids
                    else f"Latency · selected hosts · {self.graph_window_hours}h"
                )
            )
        )
        left, right, bottom = 52, width - 18, height - 33
        top = 47
        plot_width, plot_height = right - left, bottom - top
        successful = [
            sample.latency_ms
            for _host_id, samples in host_series
            for sample in samples
            if sample.success and sample.latency_ms is not None
        ]
        max_latency = max(successful, default=10.0)
        scale_max = max(10.0, max_latency * 1.2)
        for step in range(5):
            y = bottom - plot_height * step / 4
            value = scale_max * step / 4
            canvas.create_line(left, y, right, y, fill="#e7edf3")
            canvas.create_text(
                left - 8,
                y,
                text=f"{value:.0f}",
                anchor="e",
                fill="#8292a1",
                font=("Segoe UI", 8),
            )
        canvas.create_text(
            13, top + plot_height / 2, text="ms", fill="#8292a1", anchor="w"
        )
        if not host_series:
            canvas.create_text(
                width / 2,
                height / 2,
                text=(
                    "Choose hosts to display"
                    if self.hosts
                    and (
                        self.chart_samples_by_host
                        or not self.graph_host_ids
                    )
                    else "Start monitoring to build a latency history"
                ),
                fill="#8292a1",
                font=("Segoe UI", 10),
            )
            return
        all_samples = [
            sample for _host_id, samples in host_series for sample in samples
        ]
        first_timestamp = min(sample.checked_at.timestamp() for sample in all_samples)
        last_timestamp = max(sample.checked_at.timestamp() for sample in all_samples)
        timestamp_range = max(last_timestamp - first_timestamp, 1.0)

        for series_index, (host_id, samples) in enumerate(host_series):
            color = CHART_COLORS[series_index % len(CHART_COLORS)]
            points: list[tuple[float, float] | None] = []
            for sample in samples:
                x = left + plot_width * (
                    sample.checked_at.timestamp() - first_timestamp
                ) / timestamp_range
                if sample.success and sample.latency_ms is not None:
                    y = bottom - plot_height * sample.latency_ms / scale_max
                    points.append((x, y))
                else:
                    points.append(None)
            for first, second in zip(points, points[1:]):
                if first is not None and second is not None:
                    canvas.create_line(
                        *first, *second, fill=color, width=2, smooth=True
                    )
            for sample, point in zip(samples, points):
                if point:
                    canvas.create_oval(
                        point[0] - 2.5,
                        point[1] - 2.5,
                        point[0] + 2.5,
                        point[1] + 2.5,
                        fill=color,
                        outline="",
                    )
                else:
                    x = left + plot_width * (
                        sample.checked_at.timestamp() - first_timestamp
                    ) / timestamp_range
                    canvas.create_line(
                        x - 3,
                        bottom - 3,
                        x + 3,
                        bottom + 3,
                        fill=color,
                        width=2,
                    )
                    canvas.create_line(
                        x - 3,
                        bottom + 3,
                        x + 3,
                        bottom - 3,
                        fill=color,
                        width=2,
                    )
            host = next((host for host in self.hosts if host.id == host_id), None)
            name = self.hostnames.get(host_id, host.address if host else str(host_id))
            if series_index < 8:
                legend_x = left + (series_index % 4) * max(115, plot_width / 4)
                legend_y = 12 + (series_index // 4) * 15
                canvas.create_line(
                    legend_x,
                    legend_y,
                    legend_x + 12,
                    legend_y,
                    fill=color,
                    width=2,
                )
                canvas.create_text(
                    legend_x + 17,
                    legend_y,
                    text=name[:18],
                    anchor="w",
                    fill="#526779",
                    font=("Segoe UI", 8),
                )
        if len(host_series) > 8:
            canvas.create_text(
                right,
                27,
                text=f"+{len(host_series) - 8} more hosts",
                anchor="e",
                fill="#64788b",
                font=("Segoe UI", 8),
            )
        canvas.create_text(
            left,
            height - 10,
            text=datetime.fromtimestamp(first_timestamp).strftime("%H:%M:%S"),
            anchor="w",
            fill="#8292a1",
            font=("Segoe UI", 8),
        )
        canvas.create_text(
            right,
            height - 10,
            text=datetime.fromtimestamp(last_timestamp).strftime("%H:%M:%S"),
            anchor="e",
            fill="#8292a1",
            font=("Segoe UI", 8),
        )

    def _selected_chart_series(self) -> list[tuple[int, list[Sample]]]:
        return [
            (host_id, samples)
            for host_id, samples in self.chart_samples_by_host.items()
            if samples and host_id in (self.graph_host_ids or set())
        ]

    def _show_report(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Network report")
        dialog.geometry("900x390")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill="both", expand=True)
        heading = ttk.Label(frame, text="Network report", style="Title.TLabel")
        heading.pack(anchor="w", pady=(0, 8))
        report_controls = ttk.Frame(frame)
        report_controls.pack(fill="x", pady=(0, 10))
        ttk.Label(report_controls, text="Report period (hours)").pack(side="left")
        report_window_var = tk.StringVar(value=str(self.report_window_hours))
        report_window = ttk.Spinbox(
            report_controls,
            from_=1,
            to=MAX_REPORT_WINDOW_HOURS,
            textvariable=report_window_var,
            width=7,
        )
        report_window.pack(side="left", padx=(8, 8))
        report_window_var.trace_add(
            "write", lambda *_args: self._remember_report_window(report_window_var)
        )
        columns = (
            "host",
            "port",
            "samples",
            "successes",
            "loss",
            "average",
            "minimum",
            "maximum",
        )
        table = ttk.Treeview(frame, columns=columns, show="headings")
        titles = [
            ("host", "Host"),
            ("port", "Port"),
            ("samples", "Samples"),
            ("successes", "Successes"),
            ("loss", "Loss"),
            ("average", "Avg latency"),
            ("minimum", "Min latency"),
            ("maximum", "Max latency"),
        ]
        for column, title in titles:
            table.heading(column, text=title)
            table.column(column, width=110, anchor="w")
        table.pack(fill="both", expand=True)

        report_summaries: list[HostSummary] = []

        def refresh_report() -> int | None:
            try:
                hours = int(report_window_var.get())
            except ValueError:
                messagebox.showerror(
                    "Invalid report period", "Enter a whole number of hours."
                )
                return None
            if not 1 <= hours <= MAX_REPORT_WINDOW_HOURS:
                messagebox.showerror(
                    "Invalid report period",
                    f"Choose between 1 and {MAX_REPORT_WINDOW_HOURS} hours.",
                )
                return None
            self.report_window_hours = hours
            report_summaries.clear()
            report_summaries.extend(
                self.database.summaries(
                    datetime.now(timezone.utc) - timedelta(hours=hours)
                )
            )
            for item in table.get_children():
                table.delete(item)
            for summary in report_summaries:
                table.insert(
                    "",
                    "end",
                    values=(
                        summary.address,
                        summary.port,
                        summary.samples,
                        summary.successes,
                        f"{summary.loss_percent:.1f}%",
                        self._format_ms(summary.average_ms),
                        self._format_ms(summary.minimum_ms),
                        self._format_ms(summary.maximum_ms),
                    ),
                )
            heading.configure(text=f"Network report · last {hours} hour(s)")
            dialog.title(f"Network report · last {hours} hour(s)")
            return hours

        ttk.Button(
            report_controls,
            text="Update",
            command=refresh_report,
        ).pack(side="left")
        refresh_report()
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(
            buttons,
            text="Export PDF",
            style="Accent.TButton",
            command=lambda: self._save_report(report_window_var.get()),
        ).pack(side="right")
        ttk.Button(buttons, text="Close", command=dialog.destroy).pack(
            side="right", padx=(0, 8)
        )

    def _remember_report_window(self, variable: tk.StringVar) -> None:
        try:
            hours = int(variable.get())
        except ValueError:
            return
        if 1 <= hours <= MAX_REPORT_WINDOW_HOURS:
            self.report_window_hours = hours

    @staticmethod
    def _format_ms(value: float | None) -> str:
        return f"{value:.2f} ms" if value is not None else "—"

    @staticmethod
    def _format_latency_range(summary: HostSummary) -> str:
        if summary.average_ms is None:
            return "—"
        return " / ".join(
            f"{value:.1f}" if value is not None else "—"
            for value in (summary.minimum_ms, summary.average_ms, summary.maximum_ms)
        ) + " ms"

    def _save_report(self, period_value: str) -> None:
        try:
            period_hours = int(period_value)
        except ValueError:
            messagebox.showerror(
                "Invalid report period", "Enter a whole number of hours."
            )
            return
        if not 1 <= period_hours <= MAX_REPORT_WINDOW_HOURS:
            messagebox.showerror(
                "Invalid report period",
                f"Choose between 1 and {MAX_REPORT_WINDOW_HOURS} hours.",
            )
            return
        summaries = self.database.summaries(
            datetime.now(timezone.utc) - timedelta(hours=period_hours)
        )
        path = filedialog.asksaveasfilename(
            title="Save network report",
            defaultextension=".pdf",
            filetypes=[("PDF document", "*.pdf")],
            initialfile="network-monitor-report.pdf",
        )
        if not path:
            return
        try:
            export_pdf(summaries, path, period_hours=period_hours)
        except Exception as error:
            LOGGER.exception("Could not export PDF report")
            messagebox.showerror("PDF export failed", str(error))
            return
        messagebox.showinfo("Report saved", f"PDF report saved to:\n{path}")

    def _save_preferences(self) -> None:
        poll_interval = self._poll_interval()
        try:
            alert_failure_threshold = int(self.alert_threshold_var.get())
        except ValueError as error:
            raise ValueError("Alert failure threshold must be a whole number.") from error
        if poll_interval is None:
            raise ValueError("Polling interval must be between 1 and 3600 seconds.")
        if not 1 <= alert_failure_threshold <= MAX_ALERT_FAILURE_THRESHOLD:
            raise ValueError(
                f"Alert threshold must be between 1 and {MAX_ALERT_FAILURE_THRESHOLD}."
            )
        preferences = Preferences(
            poll_interval_seconds=poll_interval,
            stats_window_hours=self.stats_window_hours,
            graph_window_hours=self.graph_window_hours,
            report_window_hours=self.report_window_hours,
            graph_host_ids=sorted(self.graph_host_ids or set()),
            alerts_enabled=self.alerts_enabled_var.get(),
            alert_failure_threshold=alert_failure_threshold,
        )
        self.database.save_settings(asdict(preferences))
        self.preferences = preferences

    def _close(self) -> None:
        if self.stop_event:
            self.stop_event.set()
        try:
            self._save_preferences()
        except (OSError, ValueError) as error:
            LOGGER.exception("Could not save preferences")
            if not messagebox.askyesno(
                "Could not save settings",
                f"{error}\n\nExit without saving settings?",
            ):
                return
        self.database.close()
        self.root.destroy()


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    root = tk.Tk()
    database: MonitorDatabase | None = None
    try:
        database = MonitorDatabase()
        MonitorApp(root, database)
    except (OSError, ValueError, TypeError) as error:
        LOGGER.exception("Could not start Network Monitor")
        messagebox.showerror("Could not start Network Monitor", str(error))
        if database is not None:
            database.close()
        root.destroy()
        return
    root.mainloop()
