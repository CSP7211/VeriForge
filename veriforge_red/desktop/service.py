"""VeriForge Red — Windows Service Wrapper.

Runs the RedEngine as a background Windows service using pywin32.
Supports install / start / stop / remove via the command line::

    python -m veriforge_red.desktop.service install
    python -m veriforge_red.desktop.service start
    python -m veriforge_red.desktop.service stop
    python -m veriforge_red.desktop.service remove

The service auto-starts on boot and logs to the Windows Event Log.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback

# pywin32 imports are deferred so the module can be imported on non-Windows
# platforms (e.g. during test collection) without crashing.

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:  # pragma: no cover
    servicemanager = None  # type: ignore[assignment]
    win32event = None  # type: ignore[assignment]
    win32service = None  # type: ignore[assignment]
    win32serviceutil = None  # type: ignore[assignment]

from veriforge_red.core import RedEngine

# ── Constants ───────────────────────────────────────────────────────────────

SERVICE_NAME = "VeriForgeRed"
SERVICE_DISPLAY = "VeriForge Red Security Sentinel"
SERVICE_DESCRIPTION = (
    "Background security monitoring, threat detection, and privacy auditing "
    "for VeriForge Red."
)

logger = logging.getLogger(__name__)


# ── Logging to Windows Event Log ────────────────────────────────────────────

class _EventLogHandler(logging.Handler):
    """Emit log records to the Windows Application Event Log."""

    def __init__(self, app_name: str = SERVICE_NAME):
        super().__init__()
        self.app_name = app_name

    def emit(self, record: logging.LogRecord) -> None:
        if servicemanager is None:
            return
        msg = self.format(record)
        if record.levelno >= logging.ERROR:
            servicemanager.LogErrorMsg(msg)
        elif record.levelno >= logging.WARNING:
            servicemanager.LogWarningMsg(msg)
        else:
            servicemanager.LogInfoMsg(msg)


def _setup_logging() -> None:
    fmt = "%(asctime)s %(levelname)s %(name)s — %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if servicemanager is not None:
        evt = _EventLogHandler()
        evt.setFormatter(logging.Formatter(fmt))
        handlers.append(evt)
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)


# ── Service Class ───────────────────────────────────────────────────────────

class VeriForgeRedService(win32serviceutil.ServiceFramework if win32serviceutil else object):  # type: ignore[misc]
    """Windows service that runs RedEngine in the background."""

    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args: list):
        if win32serviceutil is None:
            raise RuntimeError("pywin32 is required to run as a Windows service")
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.engine: RedEngine | None = None
        self._running = False

    # ── Service callbacks ───────────────────────────────────────────────────

    def SvcStop(self) -> None:  # noqa: N802
        """Called when the service is asked to stop."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._running = False
        win32event.SetEvent(self.stop_event)
        if self.engine:
            self.engine.stop()
            logger.info("RedEngine stopped via service stop")

    def SvcDoRun(self) -> None:  # noqa: N802
        """Main service entry-point."""
        _setup_logging()
        logger.info("Service starting — %s", SERVICE_DISPLAY)
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        self._running = True

        try:
            self.engine = RedEngine()
            self.engine.start()
            self.engine.start_monitoring(interval=60)
            logger.info("RedEngine started and monitoring")

            # block until stop signal
            while self._running:
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                # heartbeat log
                logger.debug("Service heartbeat — engine running=%s", self.engine.running)

        except Exception as exc:
            logger.critical("Service crashed: %s", exc)
            logger.critical(traceback.format_exc())
            servicemanager.LogErrorMsg(f"VeriForge Red service error: {exc}")
            raise
        finally:
            if self.engine:
                self.engine.stop()
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )
            logger.info("Service stopped")


# ── CLI helpers ─────────────────────────────────────────────────────────────

USAGE = """\
Usage:
    python -m veriforge_red.desktop.service install     Install the service
    python -m veriforge_red.desktop.service remove      Remove the service
    python -m veriforge_red.desktop.service start       Start the service
    python -m veriforge_red.desktop.service stop        Stop the service
    python -m veriforge_red.desktop.service restart     Restart the service
    python -m veriforge_red.desktop.service debug       Run in foreground (debug)
"""


def _install() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 is required")
    win32serviceutil.InstallService(
        __spec__.parent + ".service.VeriForgeRedService",  # class path
        SERVICE_NAME,
        SERVICE_DISPLAY,
        startType=win32service.SERVICE_AUTO_START,
    )
    print(f"Service '{SERVICE_NAME}' installed (auto-start on boot).")


def _remove() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 is required")
    win32serviceutil.RemoveService(SERVICE_NAME)
    print(f"Service '{SERVICE_NAME}' removed.")


def _start() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 is required")
    win32serviceutil.StartService(SERVICE_NAME)
    print(f"Service '{SERVICE_NAME}' started.")


def _stop() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 is required")
    win32serviceutil.StopService(SERVICE_NAME)
    print(f"Service '{SERVICE_NAME}' stopped.")


def _restart() -> None:
    _stop()
    time.sleep(1)
    _start()


def _debug() -> None:
    """Run the service logic in the foreground for debugging."""
    _setup_logging()
    engine = RedEngine()
    engine.start()
    engine.start_monitoring(interval=60)
    logger.info("DEBUG MODE — RedEngine running in foreground. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        logger.info("Debug session ended.")


# ── __main__ entry-point ────────────────────────────────────────────────────

_COMMANDS: dict[str, Callable[[], None]] = {
    "install": _install,
    "remove": _remove,
    "start": _start,
    "stop": _stop,
    "restart": _restart,
    "debug": _debug,
}


def main() -> None:
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    # When Windows Service Control Manager launches us, argv[1] is the
    # service short-name (the SCM handles this automatically via
    # win32serviceutil).
    if cmd == SERVICE_NAME.lower():
        # Running under SCM — let the framework handle it.
        if win32serviceutil is None:
            raise RuntimeError("pywin32 is required")
        win32serviceutil.HandleCommandLine(VeriForgeRedService)
        return

    handler = _COMMANDS.get(cmd)
    if handler is None:
        print(f"Unknown command: {cmd}\n{USAGE}")
        sys.exit(1)

    handler()


if __name__ == "__main__":
    main()
