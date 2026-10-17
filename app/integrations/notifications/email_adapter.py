"""SMTP email notifier (company relay).

Status: implemented and tested with a fake SMTP class; not connected to a company
mail relay (none was provided). The SMTP password is resolved from the vault at
send time and never logged. Failures before the message is handed over are
retryable; a timeout/disconnect *during* the DATA phase is reported as uncertain so
the outbox does not blindly resend.
"""

from __future__ import annotations

import smtplib
import socket
from email.message import EmailMessage

from app.config import Settings
from app.integrations.notifications.base import NoProviderNotifier, Notifier, SendResult
from app.integrations.vault.base import VaultAdapter, VaultError
from app.security.redaction import Redactor


class SmtpNotifier(Notifier):
    name = "smtp"
    configured = True

    def __init__(self, *, settings: Settings, vault: VaultAdapter, redactor: Redactor, smtp_factory=smtplib.SMTP):
        self._host = settings.smtp_host or ""
        self._port = settings.smtp_port
        self._username = settings.smtp_username
        self._password_ref = settings.smtp_password_vault_ref
        self._from = settings.smtp_from or ""
        self._starttls = settings.smtp_starttls
        self._timeout = settings.smtp_timeout_seconds
        self._vault = vault
        self._redactor = redactor
        self._smtp_factory = smtp_factory

    def send(self, *, to_email: str, subject: str, body: str) -> SendResult:
        try:
            message = EmailMessage()
            message["From"] = self._from
            message["To"] = to_email
            message["Subject"] = " ".join(subject.split())
            message.set_content(body)
        except (ValueError, TypeError) as exc:
            return SendResult("failed", f"message could not be built ({type(exc).__name__})", retryable=False)
        try:
            client = self._smtp_factory(self._host, self._port, timeout=self._timeout)
        except (OSError, smtplib.SMTPException) as exc:
            return SendResult("failed", f"connect failed ({type(exc).__name__})", retryable=True)
        # Decide the result inside the session, but only return after it closes: a failure while
        # closing (QUIT) must not turn an accepted message into a retryable failure (duplicate email).
        result: SendResult | None = None
        accepted = False
        try:
            with client:
                if self._starttls:
                    client.starttls()
                if self._username and self._password_ref:
                    try:
                        password = self._vault.read(self._password_ref).reveal()
                    except VaultError as exc:
                        result = SendResult("failed", f"SMTP credential unavailable ({type(exc).__name__})", retryable=True)
                    else:
                        self._redactor.register_secret(password)
                        client.login(self._username, password)
                if result is None:
                    try:
                        client.send_message(message)
                        accepted = True
                        result = SendResult("sent", "accepted by relay")
                    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
                        result = SendResult("failed", f"rejected by relay ({type(exc).__name__})", retryable=False)
                    except smtplib.SMTPDataError as exc:
                        result = SendResult("failed", f"relay refused data (code {exc.smtp_code})", retryable=exc.smtp_code < 500)
                    except (socket.timeout, smtplib.SMTPServerDisconnected, ConnectionError) as exc:
                        result = SendResult("uncertain", f"interrupted during send ({type(exc).__name__})")
        except smtplib.SMTPAuthenticationError:
            return SendResult("failed", "SMTP authentication failed", retryable=False)
        except (OSError, smtplib.SMTPException) as exc:
            if accepted:
                return SendResult("sent", f"accepted by relay; connection closed uncleanly ({type(exc).__name__})")
            if result is not None and result.status == "uncertain":
                return result
            return SendResult("failed", f"SMTP session failed ({type(exc).__name__})", retryable=True)
        return result or SendResult("failed", "no result", retryable=True)


def build_notifier(settings: Settings, *, vault: VaultAdapter, redactor: Redactor) -> Notifier:
    if settings.notification_backend == "smtp":
        return SmtpNotifier(settings=settings, vault=vault, redactor=redactor)
    return NoProviderNotifier()
