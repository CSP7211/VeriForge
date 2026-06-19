"""Entry-point for the VeriForge Red desktop application.

Launch via::

    python -m veriforge_red.desktop

Or with the tray icon (default)::

    python -m veriforge_red.desktop.tray
"""

from veriforge_red.desktop.app import RedApp

def main() -> None:
    app = RedApp()
    app.run()


if __name__ == "__main__":
    main()
