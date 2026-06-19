"""Android notification helper for VeriForge Red.

Provides a thin wrapper around ``pyjnius`` notification APIs with helpers
for standard notifications, threat alerts, and scan-complete summaries.

All functions gracefully degrade to log messages when ``pyjnius`` is not
available (e.g., when running on desktop during development).

Example::

    from veriforge_red.mobile.notifications import show_notification
    show_notification("Scan Complete", "No threats found", priority="normal")
"""
from __future__ import annotations

from kivy.logger import Logger

# ---------------------------------------------------------------------------
# pyjnius availability
# ---------------------------------------------------------------------------

try:
    from jnius import autoclass, cast

    _ANDROID_AVAILABLE = True
except ImportError:
    _ANDROID_AVAILABLE = False
    Logger.warning("notifications: pyjnius not available — using stub mode")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CHANNEL_ID = "veriforge_red_general"
DEFAULT_CHANNEL_NAME = "General Notifications"
THREAT_CHANNEL_ID = "veriforge_red_threats"
THREAT_CHANNEL_NAME = "Threat Alerts"
SCAN_CHANNEL_ID = "veriforge_red_scans"
SCAN_CHANNEL_NAME = "Scan Results"

_notification_manager: object | None = None
_context: object | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_context():
    """Return the Android activity context (cached)."""
    global _context
    if _context is not None:
        return _context
    if not _ANDROID_AVAILABLE:
        return None
    try:
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        _context = PythonActivity.mActivity
        return _context
    except Exception as exc:
        Logger.error("notifications: cannot get context: %s", exc)
        return None


def _get_notification_manager():
    """Return the NotificationManager system service (cached)."""
    global _notification_manager
    if _notification_manager is not None:
        return _notification_manager
    context = _get_context()
    if context is None:
        return None
    try:
        _notification_manager = cast(
            "android.app.NotificationManager",
            context.getSystemService(context.NOTIFICATION_SERVICE),
        )
        return _notification_manager
    except Exception as exc:
        Logger.error("notifications: cannot get NotificationManager: %s", exc)
        return None


def _create_channel(channel_id: str, channel_name: str, importance: int | None = None) -> None:
    """Create a notification channel (required on Android O+)."""
    context = _get_context()
    nm = _get_notification_manager()
    if context is None or nm is None:
        return
    try:
        NotificationChannel = autoclass("android.app.NotificationChannel")
        if importance is None:
            NotificationManager = autoclass("android.app.NotificationManager")
            importance = NotificationManager.IMPORTANCE_DEFAULT
        channel = NotificationChannel(channel_id, channel_name, importance)
        channel.setDescription(f"Notifications for {channel_name}")
        nm.createNotificationChannel(channel)
    except Exception as exc:
        Logger.error("notifications: channel creation failed: %s", exc)


def _next_notification_id() -> int:
    """Generate a simple unique notification ID."""
    import time
    return int((time.time() * 1000) % 2_147_483_647)


def _build_notification(
    title: str,
    message: str,
    channel_id: str = DEFAULT_CHANNEL_ID,
    small_icon: object | None = None,
    auto_cancel: bool = True,
    content_intent: object | None = None,
) -> object | None:
    """Build a Notification object using the Android API.

    Returns ``None`` when not on Android or on error.
    """
    context = _get_context()
    if context is None:
        return None
    try:
        NotificationBuilder = autoclass("android.app.Notification$Builder")
        builder = NotificationBuilder(context, channel_id)
        builder.setContentTitle(title)
        builder.setContentText(message)
        builder.setStyle(
            autoclass("android.app.Notification$BigTextStyle")().bigText(message)
        )
        if small_icon is not None:
            builder.setSmallIcon(small_icon)
        else:
            builder.setSmallIcon(context.getApplicationInfo().icon)
        builder.setAutoCancel(auto_cancel)
        if content_intent is not None:
            builder.setContentIntent(content_intent)
        return builder.build()
    except Exception as exc:
        Logger.error("notifications: build failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_notification_channel(channel_id: str | None = None, channel_name: str | None = None) -> None:
    """Create a notification channel.

    On Android O+ (API 26) every notification must belong to a channel.
    This function creates the default channel used by :func:`show_notification`.

    Parameters
    ----------
    channel_id : str, optional
        Channel identifier. Defaults to ``veriforge_red_general``.
    channel_name : str, optional
        Human-readable channel name. Defaults to ``General Notifications``.
    """
    cid = channel_id or DEFAULT_CHANNEL_ID
    cname = channel_name or DEFAULT_CHANNEL_NAME
    context = _get_context()
    if context is None:
        Logger.info("notifications: stub — would create channel '%s'", cid)
        return
    try:
        _create_channel(cid, cname)
        Logger.info("notifications: created channel '%s'", cid)
    except Exception as exc:
        Logger.error("notifications: channel error: %s", exc)


def show_notification(title: str, message: str, priority: str = "normal") -> int:
    """Display a standard Android notification.

    Parameters
    ----------
    title : str
        Notification title.
    message : str
        Notification body text.
    priority : str
        One of ``low``, ``normal``, ``high``, ``urgent``.

    Returns
    -------
    int
        The notification ID (useful for later cancellation).
    """
    nm = _get_notification_manager()
    if nm is None:
        Logger.info("notifications[stub]: %s — %s", title, message)
        return 0
    create_notification_channel()
    notif = _build_notification(title, message, channel_id=DEFAULT_CHANNEL_ID)
    if notif is None:
        return 0
    notif_id = _next_notification_id()
    try:
        nm.notify(notif_id, notif)
        Logger.info("notifications: shown id=%s '%s'", notif_id, title)
    except Exception as exc:
        Logger.error("notifications: notify error: %s", exc)
    return notif_id


def show_threat_alert(threat: dict) -> int:
    """Display an urgent threat alert notification.

    Parameters
    ----------
    threat : dict
        Must contain keys: ``type``, ``severity``, ``path``.

    Returns
    -------
    int
        Notification ID.
    """
    threat_type = threat.get("type", "Unknown")
    severity = threat.get("severity", "unknown")
    path = threat.get("path", "")
    title = f"Threat: {threat_type} ({severity.upper()})"
    message = f"Detected in: {path}" if path else "Immediate action recommended"

    nm = _get_notification_manager()
    if nm is None:
        Logger.info("notifications[stub] THREAT: %s — %s", title, message)
        return 0

    context = _get_context()
    if context is None:
        return 0

    try:
        NotificationManager = autoclass("android.app.NotificationManager")
        create_notification_channel(
            THREAT_CHANNEL_ID,
            THREAT_CHANNEL_NAME,
            importance=NotificationManager.IMPORTANCE_HIGH,
        )

        # Build with default app intent (open the app when tapped)
        Intent = autoclass("android.content.Intent")
        PendingIntent = autoclass("android.app.PendingIntent")
        PythonActivity = autoclass("org.kivy.android.PythonActivity")
        intent = Intent(context, PythonActivity)
        intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP)
        pending_intent = PendingIntent.getActivity(
            context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT,
        )

        notif = _build_notification(
            title, message,
            channel_id=THREAT_CHANNEL_ID,
            auto_cancel=True,
            content_intent=pending_intent,
        )
        if notif is None:
            return 0
        notif_id = _next_notification_id()
        nm.notify(notif_id, notif)
        Logger.warning("notifications: THREAT ALERT id=%s — %s", notif_id, title)
        return notif_id
    except Exception as exc:
        Logger.error("notifications: threat alert error: %s", exc)
        return 0


def show_scan_complete(scan_result: dict) -> int:
    """Display a scan-complete summary notification.

    Parameters
    ----------
    scan_result : dict
        Must contain keys: ``grade``, ``risk_score``, ``findings_count``.

    Returns
    -------
    int
        Notification ID.
    """
    grade = scan_result.get("grade", "?")
    risk_score = scan_result.get("risk_score", 0)
    findings_count = scan_result.get("findings_count", 0)

    if findings_count == 0:
        title = "Scan Complete — Clean"
        message = "No threats detected. Your device is secure."
    else:
        title = f"Scan Complete — {findings_count} Finding(s)"
        message = f"Grade: {grade}  |  Risk Score: {risk_score}"

    nm = _get_notification_manager()
    if nm is None:
        Logger.info("notifications[stub] SCAN: %s — %s", title, message)
        return 0

    create_notification_channel(SCAN_CHANNEL_ID, SCAN_CHANNEL_NAME)
    notif = _build_notification(title, message, channel_id=SCAN_CHANNEL_ID)
    if notif is None:
        return 0
    notif_id = _next_notification_id()
    try:
        nm.notify(notif_id, notif)
        Logger.info("notifications: scan complete id=%s", notif_id)
    except Exception as exc:
        Logger.error("notifications: scan notify error: %s", exc)
    return notif_id


def cancel_notification(notification_id: int) -> None:
    """Cancel a previously shown notification.

    Parameters
    ----------
    notification_id : int
        The ID returned by ``show_notification`` or related helpers.
    """
    nm = _get_notification_manager()
    if nm is None:
        return
    try:
        nm.cancel(notification_id)
        Logger.info("notifications: cancelled id=%s", notification_id)
    except Exception as exc:
        Logger.error("notifications: cancel error: %s", exc)


def cancel_all_notifications() -> None:
    """Cancel all notifications posted by this app."""
    nm = _get_notification_manager()
    if nm is None:
        return
    try:
        nm.cancelAll()
        Logger.info("notifications: cancelled all")
    except Exception as exc:
        Logger.error("notifications: cancelAll error: %s", exc)
