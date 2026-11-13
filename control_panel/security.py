"""Local browser authentication and safe presentation helpers."""
from __future__ import annotations

import secrets
import time
import logging
import traceback
from contextlib import contextmanager
from urllib.parse import urlsplit

import bleach
from markdown_it import MarkdownIt


class LocalSecurity:
    def __init__(self, pairing_token: str | None = None):
        self.pairing_token = pairing_token or secrets.token_urlsafe(32)
        self.sessions: dict[str, tuple[str, float]] = {}

    def pair(self, token: str) -> tuple[str, str]:
        if not self.pairing_token or not secrets.compare_digest(token, self.pairing_token):
            raise ValueError("This pairing link has expired. Relaunch the app to pair a browser.")
        self.pairing_token = ""
        session, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.sessions[session] = (csrf, time.monotonic() + 12 * 3600)
        return session, csrf

    def csrf(self, session: str) -> str | None:
        value = self.sessions.get(session)
        if value and value[1] > time.monotonic():
            return value[0]
        self.sessions.pop(session, None)
        return None

    @staticmethod
    def local_host(host: str) -> bool:
        try:
            return urlsplit("http://" + host).hostname in {"127.0.0.1", "localhost", "::1"}
        except ValueError:
            return False


_markdown = MarkdownIt("commonmark", {"html": False}).enable("table")
_tags = {"p", "br", "hr", "strong", "em", "s", "ul", "ol", "li", "blockquote", "pre", "code", "a", "h1", "h2", "h3", "h4", "table", "thead", "tbody", "tr", "th", "td"}


def safe_markdown(text: str) -> str:
    return bleach.clean(
        _markdown.render(text), tags=_tags,
        attributes={"a": ["href", "title"]}, protocols={"https", "http", "mailto"}, strip=True,
    )


@contextmanager
def redacted_logging(store):
    """Filter all loggers, including SDK loggers with their own handlers."""
    previous = logging.getLogRecordFactory()
    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        record.msg = store.redact(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = store.redact("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        return record
    logging.setLogRecordFactory(factory)
    try:
        yield
    finally:
        if logging.getLogRecordFactory() is factory:
            logging.setLogRecordFactory(previous)
