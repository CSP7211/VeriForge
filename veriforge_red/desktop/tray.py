"""VeriForge Red — System Tray Integration.

Uses pystray (with PIL) to display a persistent icon in the Windows system tray.
Provides a right-click context menu, balloon notifications, and double-click
to open the main GUI.
"""

from __future__ import annotations

import logging
import os
import threading
import tkinter as tk
from typing import Callable, Optional

from PIL import Image, ImageDraw, ImageFont

try:
    import pystray
except ImportError:  # pragma: no cover
    pystray = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ── Icon Generation ─────────────────────────────────────────────────────────


def _draw_shield(draw: ImageDraw.ImageDraw, cx: int, cy: int, size: int, color: str) -> None:
    """Draw a shield polygon centred at (cx, cy)."""
    half = size // 2
    # shield shape: top flat, sides curve down to a point
    top = cy - half
    bottom = cy + half - 4
    left = cx - half + 4
    right = cx + half - 4
    mid = cy + 4
    polygon = [
        (left, top + 8),      # top-left
        (left, mid),          # mid-left
        (cx, bottom),         # bottom point
        (right, mid),         # mid-right
        (right, top + 8),     # top-right
        (cx, top),            # top centre
    ]
    draw.polygon(polygon, fill=color)


def generate_icon(size: int = 64) -> Image.Image:
    """Generate a red-shield icon on a transparent background.

    Returns a *size* x *size* RGBA PIL Image.
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # outer dark shield
    _draw_shield(draw, size // 2, size // 2, size - 4, "#8b0000")
    # inner bright red shield
    _draw_shield(draw, size // 2, size // 2, size - 14, "#c62828")
    # accent highlight
    _draw_shield(draw, size // 2, size // 2 - 2, size - 22, "#e94560")

    # letter "V" in white
    try:
        font = ImageFont.truetype("segoeui.ttf", size // 3)
    except OSError:
        font = ImageFont.load_default()
    text = "V"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (size - tw) // 2 - bbox[0]
    ty = (size - th) // 2 - bbox[1] - 1
    draw.text((tx, ty), text, fill="#ffffff", font=font)

    return img


# ── Tray Controller ─────────────────────────────────────────────────────────

class TrayController:
    """Manages the VeriForge Red system-tray icon and menu.

    Parameters
    ----------
    on_open:
        Callback invoked when the user chooses *Open VeriForge Red* or
        double-clicks the icon.
    on_scan:
        Callback invoked when the user chooses *Scan Now*.
    on_toggle_monitor:
        Callback invoked when the user toggles monitoring.
    on_settings:
        Callback invoked when the user chooses *Settings*.
    on_about:
        Callback invoked when the user chooses *About*.
    on_exit:
        Callback invoked when the user chooses *Exit*.
    """

    def __init__(
        self,
        on_open: Callable[[], None],
        on_scan: Callable[[], None],
        on_toggle_monitor: Callable[[], None],
        on_settings: Callable[[], None],
        on_about: Callable[[], None],
        on_exit: Callable[[], None],
    ) -> None:
        self._cb = {
            "open": on_open,
            "scan": on_scan,
            "toggle_monitor": on_toggle_monitor,
            "settings": on_settings,
            "about": on_about,
            "exit": on_exit,
        }
        self._icon: Optional["pystray.Icon"] = None
        self._monitoring = False
        self._security_score = 0
        self._privacy_score = 0
        self._icon_image = generate_icon(64)

    # ── Properties updated from the engine ──────────────────────────────────

    @property
    def security_score(self) -> int:
        return self._security_score

    @security_score.setter
    def security_score(self, value: int) -> None:
        self._security_score = value
        self._update_menu()

    @property
    def privacy_score(self) -> int:
        return self._privacy_score

    @privacy_score.setter
    def privacy_score(self, value: int) -> None:
        self._privacy_score = value
        self._update_menu()

    @property
    def monitoring(self) -> bool:
        return self._monitoring

    @monitoring.setter
    def monitoring(self, value: bool) -> None:
        self._monitoring = value
        self._update_menu()

    # ── Menu construction ───────────────────────────────────────────────────

    def _build_menu(self) -> "pystray.Menu":
        if pystray is None:
            raise RuntimeError("pystray is not installed")

        monitor_label = "\u25a0 Stop Monitoring" if self._monitoring else "\u25b6 Start Monitoring"
        return pystray.Menu(
            pystray.MenuItem("Open VeriForge Red", self._on_open, default=True),
            pystray.MenuItem("Scan Now", self._on_scan),
            pystray.MenuItem(monitor_label, self._on_toggle_monitor),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"Security Score: {self._security_score}%", lambda icon, item: None, enabled=False),
            pystray.MenuItem(f"Privacy Score: {self._privacy_score}%", lambda icon, item: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Settings", self._on_settings),
            pystray.MenuItem("About", self._on_about),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._on_exit),
        )

    def _update_menu(self):
        if self._icon:
            self._icon.menu = self._build_menu()
            self._icon.update_menu()

    # ── Menu handlers ───────────────────────────────────────────────────────

    def _on_open(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self._cb["open"]()

    def _on_scan(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self._cb["scan"]()

    def _on_toggle_monitor(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self._cb["toggle_monitor"]()

    def _on_settings(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self._cb["settings"]()

    def _on_about(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self._cb["about"]()

    def _on_exit(self, icon: "pystray.Icon", item: "pystray.MenuItem") -> None:
        self.stop()
        self._cb["exit"]()

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start(self) -> threading.Thread:
        """Start the tray icon in a background thread.

        Returns the thread so callers can join it if desired.
        """
        if pystray is None:
            raise RuntimeError("pystray is required for system tray integration.  Install it:  pip install pystray")

        def _run():
            self._icon = pystray.Icon(
                "veriforge_red",
                icon=self._icon_image,
                title="VeriForge Red — Security Sentinel",
                menu=self._build_menu(),
            )
            self._icon.run()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        logger.info("System tray icon started")
        return t

    def stop(self) -> None:
        """Stop the tray icon."""
        if self._icon:
            self._icon.stop()
            self._icon = None
            logger.info("System tray icon stopped")

    def notify(self, title: str, message: str, duration: float = 5.0) -> None:
        """Show a balloon notification (if the backend supports it)."""
        if self._icon:
            try:
                self._icon.notify(message, title)
            except Exception as exc:
                logger.debug("Notification not shown: %s", exc)


# ── Convenience integration with RedApp ─────────────────────────────────────

def run_with_tray(app) -> None:
    """Attach a system-tray icon to an existing *RedApp* instance.

    This is the recommended entry-point for the bundled .exe.
    """
    tray = TrayController(
        on_open=app.show,
        on_scan=lambda: (
            app.show(),
            app.notebook.select(app._tabs["Scan"]),
            app._start_scan(),
        ),
        on_toggle_monitor=app._toggle_monitoring,
        on_settings=lambda: (app.show(), app.notebook.select(app._tabs["Settings"])),
        on_about=lambda: tk.messagebox.showinfo(
            "About VeriForge Red",
            "VeriForge Red v1.0.0\nSecurity Sentinel Platform\n\n(c) 2024 VeriForge",
        ),
        on_exit=app.destroy,
    )

    # sync initial state
    state = app.engine.state
    tray.security_score = state.get("security_score", 0)
    tray.privacy_score = state.get("privacy_score", 0)

    tray.start()
    app.hide()  # start hidden; user opens via tray
    app.run()
    tray.stop()


if __name__ == "__main__":
    import tempfile
    icon = generate_icon(64)
    path = os.path.join(tempfile.gettempdir(), "veriforge_red_icon.png")
    icon.save(path)
    print(f"Preview icon written to: {path}")
