#!/usr/bin/env python3
"""
Mk.03-Storage-Cleanup-Tool - macOS disk usage and cleanup utility.

This script provides a Tkinter-based GUI that helps inspect large directories,
remove caches and other leftover files, securely delete selected paths, and
empty the Trash.
"""

from __future__ import annotations

import os
import queue
import random
import shutil
import stat
import string
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


SCAN_STOP_SENTINEL = object()


def human_size(num_bytes: int) -> str:
    """Convert byte counts into human readable strings."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    units = ["KB", "MB", "GB", "TB", "PB"]
    size = float(num_bytes)
    for unit in units:
        size /= 1024.0
        if size < 1024.0:
            return f"{size:.2f} {unit}"
    return f"{size:.2f} EB"


def iter_cache_paths() -> Iterable[Path]:
    """Yield common macOS cache directories that can usually be cleared safely."""
    home = Path.home()
    candidates = [
        home / "Library" / "Caches",
        home / "Library" / "Logs",
        home / "Library" / "Containers" / "com.apple.mail" / "Data" / "Library" / "Caches",
        home / "Library" / "Safari" / "Favicon Cache",
        home / "Library" / "Application Support" / "Slack" / "Service Worker" / "CacheStorage",
        home / "Library" / "Application Support" / "Code" / "Cache",
        home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Cache",
        home / "Library" / "Application Support" / "Firefox" / "Profiles",
        home / "Library" / "Application Support" / "Spotify" / "Cache",
        home / ".Trash",
    ]
    for path in candidates:
        if path.exists():
            yield path


def secure_wipe_file(path: Path) -> None:
    """
    Attempt to wipe a file by overwriting with random data before deletion.

    Note: This is a best-effort approach and does not guarantee compliance with
    secure erasure standards. For SSDs, firmware-level wear levelling can keep
    prior blocks alive. We still provide an overwrite pass to minimise remnants.
    """
    try:
        if not path.is_file() or not os.access(path, os.W_OK):
            return
        length = path.stat().st_size
        if length == 0:
            return
        with path.open("r+b", buffering=0) as f:
            chunk = bytearray(os.urandom(min(length, 1024 * 1024)))
            remaining = length
            while remaining > 0:
                write_size = min(len(chunk), remaining)
                if write_size != len(chunk):
                    chunk = bytearray(os.urandom(write_size))
                f.write(chunk)
                remaining -= write_size
                f.flush()
                os.fsync(f.fileno())
    except Exception:
        # We swallow errors on wipe to ensure delete proceeds.
        pass


def secure_delete_path(path: Path) -> Tuple[bool, Optional[str]]:
    """
    Securely delete files or directories. Returns (success, error_message).

    For directories, all contained files are overwritten before removal.
    """
    try:
        if path.is_symlink():
            path.unlink(missing_ok=True)  # Avoid resolving symlinks
            return True, None

        if path.is_file():
            secure_wipe_file(path)
            path.unlink(missing_ok=True)
            return True, None

        if path.is_dir():
            for root, dirs, files in os.walk(path, topdown=False):
                root_path = Path(root)
                for name in files:
                    secure_wipe_file(root_path / name)
                    try:
                        (root_path / name).unlink(missing_ok=True)
                    except Exception:
                        pass
                for name in dirs:
                    subdir = root_path / name
                    try:
                        subdir.chmod(subdir.stat().st_mode | stat.S_IWUSR)
                    except Exception:
                        pass
                    try:
                        subdir.rmdir()
                    except OSError:
                        pass
            shutil.rmtree(path, ignore_errors=True)
            return True, None

        # For anything else (e.g., device nodes), attempt unlink.
        path.unlink(missing_ok=True)
        return True, None
    except Exception as exc:
        return False, str(exc)


def estimate_directory_size(path: Path) -> int:
    """Compute recursive size of a directory or file."""
    try:
        if not path.exists():
            return 0
        if path.is_symlink():
            return 0
        if path.is_file():
            return path.stat().st_size
        total = 0
        for root, _, files in os.walk(path, onerror=lambda e: None):
            root_path = Path(root)
            for file in files:
                full_path = root_path / file
                try:
                    if full_path.is_symlink():
                        continue
                    total += full_path.stat().st_size
                except (FileNotFoundError, PermissionError):
                    continue
        return total
    except (FileNotFoundError, PermissionError):
        return 0


@dataclass
class DirectoryInfo:
    path: Path
    size: int


class ScanWorker(threading.Thread):
    """Background thread to scan directories without blocking the GUI."""

    def __init__(self, root_path: Path, out_queue: queue.Queue, limit: int = 30) -> None:
        super().__init__(daemon=True)
        self.root_path = root_path
        self.out_queue = out_queue
        self.limit = limit
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        entries: List[DirectoryInfo] = []
        try:
            entry_list = sorted(list(self.root_path.iterdir()), key=lambda p: p.name.lower())
            total = len(entry_list)
            self.out_queue.put(("START", {"total": total, "root": self.root_path}))
            scan_start = time.time()
            for index, entry in enumerate(entry_list, start=1):
                if self._stop_event.is_set():
                    break
                try:
                    size = estimate_directory_size(entry)
                    info = DirectoryInfo(path=entry, size=size)
                    entries.append(info)
                    self.out_queue.put(
                        (
                            "PROGRESS",
                            {
                                "index": index,
                                "total": total,
                                "info": info,
                                "elapsed": time.time() - scan_start,
                            },
                        )
                    )
                except PermissionError:
                    self.out_queue.put(("ERROR", f"권한이 없어 스킵: {entry}"))
                except FileNotFoundError:
                    continue
        finally:
            entries.sort(key=lambda x: x.size, reverse=True)
            self.out_queue.put(("DONE", entries[: self.limit]))


class Mk03StorageCleanupToolApp(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Mk.03-Storage-Cleanup-Tool")
        self.geometry("960x620")
        self.minsize(880, 560)
        self.configure(background="#eef1f6")

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        base_bg = "#eef1f6"
        header_bg = "#dce4f5"
        card_bg = "#ffffff"
        accent = "#2563eb"
        accent_active = "#1d4ed8"
        danger = "#dc2626"
        danger_active = "#b91c1c"
        subtle_text = "#4b5563"
        title_text = "#0f172a"
        subtitle_text = "#334155"
        even_row = "#f4f7fb"
        odd_row = "#ffffff"

        self.theme_colors = {
            "base_bg": base_bg,
            "card_bg": card_bg,
            "accent": accent,
            "danger": danger,
            "even_row": even_row,
            "odd_row": odd_row,
            "progress_bg": "#e5edff",
        }

        self.style.configure("Body.TFrame", background=base_bg)
        self.style.configure("Header.TFrame", background=header_bg)
        self.style.configure("Header.TLabel", background=header_bg, foreground="#111827", font=("Helvetica", 11, "bold"))
        self.style.configure("Body.TLabel", background=base_bg, foreground="#111827", font=("Helvetica", 10))
        self.style.configure("Title.TLabel", background=header_bg, foreground=title_text, font=("Helvetica Neue", 16, "bold"))
        self.style.configure("Subtitle.TLabel", background=header_bg, foreground=subtitle_text, font=("Helvetica", 11))
        self.style.configure("Badge.TLabel", background=accent, foreground="#ffffff", font=("Helvetica", 9, "bold"), padding=(10, 4))
        self.style.configure("DialogTitle.TLabel", background=card_bg, foreground=title_text, font=("Helvetica Neue", 14, "bold"))
        self.style.configure("CardBody.TLabel", background=card_bg, foreground="#1f2937", font=("Helvetica", 10))
        self.style.configure(
            "Card.TLabelframe",
            background=card_bg,
            borderwidth=0,
            relief="flat",
            padding=(16, 12, 16, 16),
        )
        self.style.configure(
            "Card.TLabelframe.Label",
            background=card_bg,
            foreground="#1f2937",
            font=("Helvetica", 11, "bold"),
        )
        self.style.configure("Secondary.TFrame", background=card_bg)
        self.style.configure("Card.TFrame", background=card_bg)
        self.style.configure("Status.TFrame", background=base_bg)
        self.style.configure("Status.TLabel", background=base_bg, foreground=subtle_text, font=("Helvetica", 10))
        self.style.configure(
            "Primary.TButton",
            background=accent,
            foreground="#ffffff",
            padding=(14, 6),
            font=("Helvetica", 10, "bold"),
            borderwidth=0,
            focusthickness=3,
            focuscolor=accent_active,
        )
        self.style.map(
            "Primary.TButton",
            background=[("active", accent_active), ("pressed", accent_active)],
            foreground=[("disabled", "#d1d5db")],
        )
        self.style.configure(
            "Secondary.TButton",
            background=card_bg,
            foreground=accent,
            padding=(12, 6),
            font=("Helvetica", 10, "bold"),
            borderwidth=1,
            focusthickness=3,
            focuscolor=accent,
        )
        self.style.map(
            "Secondary.TButton",
            background=[("active", "#e0e7ff"), ("pressed", "#c7d2fe")],
            foreground=[("disabled", "#9ca3af")],
        )
        self.style.configure(
            "Danger.TButton",
            background=danger,
            foreground="#ffffff",
            padding=(12, 6),
            font=("Helvetica", 10, "bold"),
            borderwidth=0,
            focusthickness=3,
            focuscolor=danger_active,
        )
        self.style.map(
            "Danger.TButton",
            background=[("active", danger_active), ("pressed", danger_active)],
            foreground=[("disabled", "#fca5a5")],
        )
        self.style.configure("Treeview", background=card_bg, fieldbackground=card_bg, borderwidth=0, font=("Helvetica", 10))
        self.style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        self.style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#1f2937")])
        self.style.configure(
            "Release.Horizontal.TProgressbar",
            troughcolor=card_bg,
            bordercolor=card_bg,
            thickness=10,
            background=accent,
            lightcolor=accent,
            darkcolor=accent_active,
        )
        self.style.configure(
            "Accent.TCheckbutton",
            background=card_bg,
            foreground="#1f2937",
            font=("Helvetica", 10),
        )
        self.style.map(
            "Accent.TCheckbutton",
            background=[("active", "#e0e7ff"), ("selected", "#dbeafe")],
            foreground=[("disabled", "#9ca3af")],
        )

        self.selected_root = tk.StringVar(value=str(Path.home()))
        self.status_text = tk.StringVar(value="준비 완료")

        self.progress_value = 0
        self.progress_max = 100

        self.scan_thread: Optional[ScanWorker] = None
        self.scan_queue: queue.Queue = queue.Queue()
        self.current_entries: List[DirectoryInfo] = []
        self.optimization_window: Optional[tk.Toplevel] = None
        self.optimization_vars: dict[str, tk.BooleanVar] = {}

        self._build_layout()
        self.status_text.set("검사를 시작하려면 '검사 시작'을 누르세요.")
        self.after(200, self._poll_queue)

    # GUI construction -------------------------------------------------
    def _build_layout(self) -> None:
        container = ttk.Frame(self, padding=(16, 16, 16, 12), style="Body.TFrame")
        container.pack(fill=tk.BOTH, expand=True)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=0)
        container.rowconfigure(1, weight=1)
        container.rowconfigure(2, weight=0)

        header = ttk.Frame(container, padding=(20, 12), style="Header.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="대상 경로", style="Header.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 12))
        entry = ttk.Entry(header, textvariable=self.selected_root)
        entry.grid(row=0, column=1, sticky="ew")
        button_width = 12
        ttk.Button(
            header,
            text="찾기",
            style="Secondary.TButton",
            command=self.choose_directory,
            width=button_width,
        ).grid(row=0, column=2, padx=(12, 0), sticky="e")
        ttk.Button(
            header,
            text="검사 시작",
            style="Primary.TButton",
            command=self.start_scan,
            width=button_width,
        ).grid(row=0, column=3, padx=(12, 0), sticky="e")
        ttk.Button(
            header,
            text="삭제",
            style="Danger.TButton",
            command=self.delete_selected,
            width=button_width,
        ).grid(row=0, column=4, padx=(12, 0), sticky="e")
        ttk.Button(
            header,
            text="최적화",
            style="Secondary.TButton",
            command=self.open_optimization_window,
            width=button_width,
        ).grid(row=0, column=5, padx=(12, 0), sticky="e")
        main_frame = ttk.Frame(container, style="Body.TFrame")
        main_frame.grid(row=1, column=0, sticky="nsew", pady=(16, 0))
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=0)

        tree_card = ttk.LabelFrame(main_frame, text="검사 결과", style="Card.TLabelframe")
        tree_card.grid(row=0, column=0, sticky="nsew")
        tree_card.columnconfigure(0, weight=1)
        tree_card.rowconfigure(0, weight=0)
        tree_card.rowconfigure(1, weight=1)

        tree_toolbar = ttk.Frame(tree_card, style="Secondary.TFrame")
        tree_toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(tree_toolbar, text="현재 경로", style="CardBody.TLabel").pack(side=tk.LEFT)
        self.root_display = ttk.Label(
            tree_toolbar,
            textvariable=self.selected_root,
            style="CardBody.TLabel",
            wraplength=520,
            justify=tk.LEFT,
        )
        self.root_display.pack(side=tk.LEFT, padx=(8, 0))

        columns = ("path", "size")
        self.tree = ttk.Treeview(tree_card, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("path", text="경로")
        self.tree.heading("size", text="용량")
        self.tree.column("path", anchor="w", width=520, stretch=True)
        self.tree.column("size", anchor="e", width=120, stretch=False)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=(0, 4), pady=(4, 4))
        self.tree.tag_configure("even", background=self.theme_colors["even_row"], foreground="#111827")
        self.tree.tag_configure("odd", background=self.theme_colors["odd_row"], foreground="#111827")

        tree_scroll = ttk.Scrollbar(tree_card, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll.grid(row=1, column=1, sticky="ns", pady=(4, 4))
        self.tree.configure(yscrollcommand=tree_scroll.set)

        log_frame = ttk.LabelFrame(main_frame, text="활동 로그", style="Card.TLabelframe")
        log_frame.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            height=6,
            wrap="word",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#0f172a",
            highlightcolor="#0f172a",
            relief=tk.FLAT,
            background="#111827",
            foreground="#e2e8f0",
            insertbackground="#e2e8f0",
            font=("Menlo", 10),
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.configure(state=tk.DISABLED)

        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        progress_frame = ttk.Frame(container, style="Header.TFrame", padding=(20, 12))
        progress_frame.grid(row=2, column=0, sticky="ew")
        progress_frame.columnconfigure(0, weight=1)
        self.progress_canvas = tk.Canvas(
            progress_frame,
            height=24,
            highlightthickness=0,
            bd=0,
            background=self.theme_colors["card_bg"],
        )
        self.progress_canvas.grid(row=0, column=0, sticky="ew")
        self.progress_canvas.bind("<Configure>", self._on_progress_resize)
        self.progress_background = self.progress_canvas.create_rectangle(
            0,
            0,
            0,
            0,
            fill=self.theme_colors["progress_bg"],
            outline=self.theme_colors["accent"],
            width=1,
        )
        self.progress_fill = self.progress_canvas.create_rectangle(
            0,
            0,
            0,
            0,
            fill=self.theme_colors["accent"],
            outline="",
        )
        self._refresh_progress_canvas()
        status_bar = ttk.Label(self, textvariable=self.status_text, anchor="w", style="Status.TLabel", padding=(16, 6))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=(0, 12))

    # Basic helpers ----------------------------------------------------
    def _on_progress_resize(self, event: tk.Event) -> None:
        self._refresh_progress_canvas(event.width, event.height)

    def _refresh_progress_canvas(self, width: Optional[int] = None, height: Optional[int] = None) -> None:
        if not hasattr(self, "progress_canvas"):
            return
        canvas = self.progress_canvas
        if width is None or width <= 0:
            width = canvas.winfo_width() or canvas.winfo_reqwidth()
        if height is None or height <= 0:
            height = canvas.winfo_height() or canvas.winfo_reqheight() or 24
        ratio = 0.0
        if self.progress_max > 0:
            ratio = max(0.0, min(self.progress_value / self.progress_max, 1.0))
        fill_width = int(width * ratio)
        canvas.coords(self.progress_background, 0, 0, width, height)
        canvas.coords(self.progress_fill, 0, 0, fill_width, height)

    def log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def choose_directory(self) -> None:
        selection = filedialog.askdirectory(initialdir=self.selected_root.get())
        if selection:
            self.selected_root.set(selection)
            self.status_text.set(f"선택된 경로: {selection}")

    # Scanning ---------------------------------------------------------
    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("스캔 진행 중", "이전 스캔이 완료될 때까지 기다려 주세요.")
            return

        root = Path(self.selected_root.get()).expanduser()
        if not root.exists():
            messagebox.showerror("경로 오류", f"경로를 찾을 수 없습니다: {root}")
            return

        self.tree.delete(*self.tree.get_children())
        self.current_entries = []
        self.status_text.set(f"스캔 중: {root}")
        self.log(f"디렉토리 스캔 시작: {root}")
        self.progress_value = 0
        self.progress_max = 100
        self._refresh_progress_canvas()

        self.scan_thread = ScanWorker(root, self.scan_queue)
        self.scan_thread.start()

    def _poll_queue(self) -> None:
        try:
            while True:
                message = self.scan_queue.get_nowait()
                self._handle_queue_message(message)
        except queue.Empty:
            pass
        finally:
            self.after(200, self._poll_queue)

    def _handle_queue_message(self, payload: Tuple[str, object]) -> None:
        label, value = payload
        if label == "START" and isinstance(value, dict):
            total = value.get("total", 0) or 0
            root = value.get("root")
            self.progress_max = max(total, 1)
            self.progress_value = 0
            self._refresh_progress_canvas()
            if isinstance(root, Path):
                self.status_text.set(f"스캔 시작: {root}")
        elif label == "PROGRESS" and isinstance(value, dict):
            info = value.get("info")
            index = value.get("index", 0) or 0
            total = value.get("total", 0) or 0
            elapsed = value.get("elapsed", 0.0) or 0.0
            if isinstance(info, DirectoryInfo):
                self.status_text.set(f"스캔 중 ({index}/{max(total,1)}): {info.path}")
            self.progress_value = index
            self.progress_max = max(total, 1)
            self._refresh_progress_canvas()
        elif label == "ERROR":
            self.log(str(value))
        elif label == "DONE":
            entries = value if isinstance(value, list) else []
            self._populate_tree(entries)
            self.status_text.set("스캔 완료")
            self.progress_value = self.progress_max
            self._refresh_progress_canvas()
            self.log("디렉토리 스캔 완료")

    def _populate_tree(self, entries: List[DirectoryInfo]) -> None:
        self.current_entries = entries
        self.tree.delete(*self.tree.get_children())
        for index, entry in enumerate(entries):
            tag = "even" if index % 2 == 0 else "odd"
            self.tree.insert(
                "",
                tk.END,
                iid=str(entry.path),
                values=(str(entry.path), human_size(entry.size)),
                tags=(tag,),
            )

    # Actions ----------------------------------------------------------
    def _selected_paths(self) -> List[Path]:
        paths = []
        for item in self.tree.selection():
            paths.append(Path(item))
        return paths

    def delete_selected(self) -> None:
        paths = self._selected_paths()
        if not paths:
            messagebox.showinfo("선택 없음", "삭제할 항목을 먼저 선택하세요.")
            return

        total_size = sum(estimate_directory_size(path) for path in paths)
        details = "\n".join(f"- {path} ({human_size(estimate_directory_size(path))})" for path in paths)
        confirm = messagebox.askyesno(
            "삭제 확인",
            f"다음 항목을 삭제합니다:\n\n{details}\n\n총 용량: {human_size(total_size)}\n\n계속 진행할까요?",
        )
        if not confirm:
            return

        self.log("보안 삭제 시작")
        failures = []
        for path in paths:
            success, error = secure_delete_path(path)
            if success:
                self.log(f"삭제 완료: {path}")
            else:
                self.log(f"삭제 실패: {path} ({error})")
                failures.append(path)

        if failures:
            messagebox.showwarning(
                "삭제 실패",
                f"일부 항목을 삭제하지 못했습니다.\n수동으로 권한을 확인하세요.\n\n미삭제 항목:\n"
                + "\n".join(str(p) for p in failures),
            )
        else:
            messagebox.showinfo("삭제 완료", "선택한 항목을 모두 삭제했습니다.")
        self.start_scan()

    def empty_trash(self) -> None:
        trash = Path.home() / ".Trash"
        if not trash.exists():
            messagebox.showinfo("휴지통", "휴지통이 비어 있습니다.")
            return
        contents = list(trash.iterdir())
        if not contents:
            messagebox.showinfo("휴지통", "휴지통이 비어 있습니다.")
            return

        total = sum(estimate_directory_size(path) for path in contents)
        confirm = messagebox.askyesno(
            "휴지통 비우기",
            f"휴지통의 {len(contents)}개 항목을 완전히 삭제합니다.\n"
            f"총 용량: {human_size(total)}\n\n계속할까요?",
        )
        if not confirm:
            return

        failures = []
        for item in contents:
            success, error = secure_delete_path(item)
            if not success:
                failures.append((item, error))

        if failures:
            failure_text = "\n".join(f"{path}: {err}" for path, err in failures if err)
            messagebox.showwarning("일부 삭제 실패", f"다음 항목은 삭제하지 못했습니다:\n{failure_text}")
        else:
            messagebox.showinfo("휴지통 비우기", "휴지통을 비웠습니다.")
        self.log("휴지통 삭제 요청 처리")
        self.start_scan()

    def clean_caches(self) -> None:
        cache_paths = list(iter_cache_paths())
        if not cache_paths:
            messagebox.showinfo("캐시 정리", "정리 가능한 캐시 경로를 찾지 못했습니다.")
            return

        entries = []
        total = 0
        for path in cache_paths:
            size = estimate_directory_size(path)
            if size == 0:
                continue
            entries.append((path, size))
            total += size

        if not entries:
            messagebox.showinfo("캐시 정리", "정리할 캐시 파일의 용량이 없습니다.")
            return

        detail_lines = "\n".join(f"- {path} ({human_size(size)})" for path, size in entries)
        confirm = messagebox.askyesno(
            "캐시 정리",
            f"다음 캐시 경로를 삭제합니다:\n\n{detail_lines}\n\n총 용량: {human_size(total)}\n\n계속할까요?",
        )
        if not confirm:
            return

        failures = []
        for path, _ in entries:
            success, error = secure_delete_path(path)
            if not success:
                failures.append((path, error))
        if failures:
            fail_text = "\n".join(f"{path}: {err}" for path, err in failures if err)
            messagebox.showwarning("캐시 정리 실패", f"일부 경로를 정리하지 못했습니다:\n{fail_text}")
        else:
            messagebox.showinfo("캐시 정리 완료", "선택된 캐시를 정리했습니다.")
        self.log("캐시 정리 실행 완료")
        self.start_scan()

    # Optimization -----------------------------------------------------
    def open_optimization_window(self) -> None:
        if self.optimization_window and self.optimization_window.winfo_exists():
            self.optimization_window.lift()
            self.optimization_window.focus_force()
            return

        self.optimization_window = tk.Toplevel(self)
        self.optimization_window.title("최적화 도구")
        self.optimization_window.resizable(False, False)
        self.optimization_window.transient(self)
        self.optimization_window.grab_set()
        self.optimization_window.configure(background=self.theme_colors["base_bg"])

        options = [
            ("cache", "캐시 정리", "시스템 및 앱 캐시, 로그 폴더를 정리합니다."),
            ("downloads", "다운로드 폴더 정리", "다운로드 폴더의 모든 항목을 즉시 삭제합니다."),
            ("trash", "휴지통 비우기", "현재 휴지통을 완전히 비웁니다."),
            (
                "xcode",
                "Xcode DerivedData 정리",
                "Xcode 빌드 캐시(~/Library/Developer/Xcode/DerivedData)를 삭제합니다.",
            ),
            (
                "mail",
                "메일 첨부파일 정리",
                "Mail 앱 다운로드 파일(~/Library/Containers/.../Mail Downloads)을 삭제합니다.",
            ),
        ]

        self.optimization_vars = {}
        frame = ttk.Frame(self.optimization_window, padding=16, style="Card.TFrame")
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        ttk.Label(frame, text="빠른 최적화 작업", style="DialogTitle.TLabel").pack(anchor="w")
        ttk.Label(
            frame,
            text="정리할 항목을 선택한 뒤 실행을 누르면 즉시 정리가 시작됩니다.",
            style="CardBody.TLabel",
        ).pack(anchor="w", pady=(4, 12))
        for key, label, description in options:
            var = tk.BooleanVar(value=True)
            self.optimization_vars[key] = var
            check = ttk.Checkbutton(frame, text=label, variable=var, style="Accent.TCheckbutton")
            check.pack(anchor="w", pady=(8, 0))
            ttk.Label(
                frame,
                text=description,
                foreground="#4b5563",
                wraplength=320,
                justify=tk.LEFT,
                style="CardBody.TLabel",
            ).pack(anchor="w", padx=(24, 0))

        button_frame = ttk.Frame(frame, style="Card.TFrame")
        button_frame.pack(fill=tk.X, pady=(20, 0))
        ttk.Button(button_frame, text="실행", style="Primary.TButton", command=self._run_optimization_tasks).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="닫기", style="Secondary.TButton", command=self._close_optimization_window).pack(
            side=tk.RIGHT, padx=(0, 12)
        )

        self.optimization_window.protocol("WM_DELETE_WINDOW", self._close_optimization_window)

    def _close_optimization_window(self) -> None:
        if self.optimization_window and self.optimization_window.winfo_exists():
            self.optimization_window.grab_release()
            self.optimization_window.destroy()
        self.optimization_window = None

    def _run_optimization_tasks(self) -> None:
        if not any(var.get() for var in self.optimization_vars.values()):
            messagebox.showinfo("최적화", "실행할 항목을 선택하세요.")
            return

        executed = []
        if self.optimization_vars.get("cache") and self.optimization_vars["cache"].get():
            self.clean_caches()
            executed.append("캐시 정리")
        if self.optimization_vars.get("downloads") and self.optimization_vars["downloads"].get():
            self.clean_downloads()
            executed.append("다운로드 정리")
        if self.optimization_vars.get("trash") and self.optimization_vars["trash"].get():
            self.empty_trash()
            executed.append("휴지통 비우기")
        if self.optimization_vars.get("xcode") and self.optimization_vars["xcode"].get():
            self.clean_xcode_derived_data()
            executed.append("Xcode DerivedData 정리")
        if self.optimization_vars.get("mail") and self.optimization_vars["mail"].get():
            self.clean_mail_downloads()
            executed.append("메일 첨부파일 정리")

        if executed:
            self.log(f"최적화 항목 실행: {', '.join(executed)}")
        self._close_optimization_window()

    def clean_downloads(self) -> None:
        downloads = Path.home() / "Downloads"
        if not downloads.exists():
            messagebox.showinfo("다운로드 정리", "다운로드 폴더를 찾지 못했습니다.")
            return

        candidates: List[Tuple[Path, int]] = []
        for item in downloads.iterdir():
            if item.name.startswith("."):
                continue
            try:
                item.stat()
            except (FileNotFoundError, PermissionError):
                continue
            size = estimate_directory_size(item)
            if size == 0:
                continue
            candidates.append((item, size))

        if not candidates:
            messagebox.showinfo("다운로드 정리", "삭제할 다운로드 항목이 없습니다.")
            return

        details = "\n".join(f"- {path.name} ({human_size(size)})" for path, size in candidates)
        confirm = messagebox.askyesno(
            "다운로드 정리",
            "다운로드 폴더의 모든 항목을 삭제합니다.\n삭제 후 되돌릴 수 없습니다.\n\n"
            f"{details}\n\n계속 진행하시겠습니까?",
        )
        if not confirm:
            return

        failures = []
        for path, _ in candidates:
            success, error = secure_delete_path(path)
            if not success:
                failures.append((path, error))
        if failures:
            fail_text = "\n".join(f"{path}: {err}" for path, err in failures if err)
            messagebox.showwarning("일부 삭제 실패", f"다음 항목은 삭제하지 못했습니다:\n{fail_text}")
        else:
            messagebox.showinfo("다운로드 정리 완료", "다운로드 폴더의 모든 항목을 삭제했습니다.")
        self.start_scan()

    def clean_xcode_derived_data(self) -> None:
        target = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
        if not target.exists():
            messagebox.showinfo("Xcode DerivedData", "DerivedData 폴더를 찾지 못했습니다.")
            return
        size = estimate_directory_size(target)
        if size == 0:
            messagebox.showinfo("Xcode DerivedData", "삭제할 빌드 캐시가 없습니다.")
            return
        confirm = messagebox.askyesno(
            "Xcode DerivedData 정리",
            f"Xcode 빌드 캐시를 삭제합니다.\n총 용량: {human_size(size)}\n\n계속할까요?",
        )
        if not confirm:
            return
        success, error = secure_delete_path(target)
        if success:
            messagebox.showinfo("정리 완료", "DerivedData 폴더를 삭제했습니다.")
        else:
            messagebox.showwarning("정리 실패", f"DerivedData 삭제에 실패했습니다: {error}")
        self.start_scan()

    def clean_mail_downloads(self) -> None:
        target = (
            Path.home()
            / "Library"
            / "Containers"
            / "com.apple.mail"
            / "Data"
            / "Library"
            / "Mail Downloads"
        )
        if not target.exists():
            messagebox.showinfo("메일 첨부파일 정리", "Mail Downloads 폴더를 찾지 못했습니다.")
            return
        contents = list(target.iterdir())
        if not contents:
            messagebox.showinfo("메일 첨부파일 정리", "삭제할 첨부파일이 없습니다.")
            return

        total = sum(estimate_directory_size(path) for path in contents)
        confirm = messagebox.askyesno(
            "메일 첨부파일 정리",
            f"Mail 앱 첨부파일을 삭제합니다.\n항목: {len(contents)}개 · 총 용량: {human_size(total)}\n\n계속할까요?",
        )
        if not confirm:
            return

        failures = []
        for item in contents:
            success, error = secure_delete_path(item)
            if not success:
                failures.append((item, error))
        if failures:
            failure_text = "\n".join(f"{path}: {err}" for path, err in failures if err)
            messagebox.showwarning("일부 삭제 실패", f"다음 항목은 삭제하지 못했습니다:\n{failure_text}")
        else:
            messagebox.showinfo("메일 첨부파일 정리", "Mail Downloads 폴더를 비웠습니다.")
        self.start_scan()

def main() -> None:
    app = Mk03StorageCleanupToolApp()
    app.mainloop()


if __name__ == "__main__":
    main()
