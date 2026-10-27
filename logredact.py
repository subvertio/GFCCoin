"""
Keeps private data out of the node's logs.

Phone numbers reach the logs through the HTTP client (httpx logs every request URL, and the
Twilio lookup URL contains the number), and one-time verify link codes through uvicorn's access
log (GET /verify?c=<code>). A filter on every log handler rewrites them before they're written:

- phone numbers (+ and 8-15 digits, also URL-encoded as %2B) keep only their last two digits: +...98
- verify link codes become c=<hidden>

install() runs at startup, after uvicorn has set up its loggers. The database never stores a
number in the clear (phone_verify.py keeps an HMAC); with this, the logs don't either.
"""
import logging
import re

_PHONE = re.compile(r"(\+|%2[bB])(\d{6,13})(\d{2})(?!\d)")
_LINK_CODE = re.compile(r"([?&]c=)[A-Za-z0-9_-]{8,}")


def redact(text: str) -> str:
    text = _PHONE.sub(lambda m: "+..." + m.group(3), text)
    return _LINK_CODE.sub(lambda m: m.group(1) + "<hidden>", text)


def _clean(value):
    return redact(value) if isinstance(value, str) else value


class RedactFilter(logging.Filter):
    """
    Redacts a record's message and each of its arguments in place; never drops a record.
    The arguments keep their shape, because some formatters read them directly (uvicorn's
    access log formats client, method, path and status from record.args).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(_clean(a) for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: _clean(v) for k, v in record.args.items()}
        return True


_FILTER = RedactFilter()


def install():
    """Adds the filter to every handler of the root logger and of uvicorn's loggers (safe to call twice)."""
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore"):
        for handler in logging.getLogger(name).handlers:
            if _FILTER not in handler.filters:
                handler.addFilter(_FILTER)
