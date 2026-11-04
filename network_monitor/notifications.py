import logging
import sys

LOGGER = logging.getLogger(__name__)


def notify(title: str, message: str) -> None:
    """Send an operating-system notification or raise a clear backend error."""
    try:
        if sys.platform == "win32":
            from winotify import Notification

            Notification(
                app_id="Network Monitor",
                title=title,
                msg=message,
            ).show()
        else:
            from plyer import notification

            notification.notify(
                title=title,
                message=message,
                app_name="Network Monitor",
                timeout=8,
            )
    except ImportError as error:
        raise RuntimeError(
            "Desktop notifications are unavailable; install the app dependencies."
        ) from error
    except Exception as error:
        LOGGER.exception("Desktop notification failed")
        raise RuntimeError(f"Desktop notification failed: {error}") from error
