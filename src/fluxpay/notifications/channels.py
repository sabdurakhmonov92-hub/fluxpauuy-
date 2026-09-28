"""Notification transport channels for Telegram and email (Task 43).

==============================================================================
CONTENT CONTENT LAW: PLAINTEXT ONLY
==============================================================================
Both channels (Telegram and SendGrid email) send PLAINTEXT content exclusively.

Telegram: parse_mode is deliberately OMITTED from every request.
WHY: notification bodies include payment IDs, amounts, currencies, and hold
reasons — arbitrary string content from merchant and agent inputs. If HTML
parse_mode were enabled, any '<' or '>' in a reason string would be
misinterpreted as markup, producing broken messages or, worse, crafted inputs
could inject Telegram formatting tags (bold, links, code). Plaintext Telegram
is visually plainer but safe. Emoji in the message body provide visual triage
without parse_mode (emoji are Unicode, not HTML).

Email: content-type text/plain. Payment notification emails are operational
notices, not marketing content. HTML email = tracking pixels, phishing-style
styling, and rendering bugs across email clients. Plain text is unambiguous,
non-phishable, and universally supported.

==============================================================================
RETRY / FAIL-LOUD DISCIPLINE
==============================================================================
Channels implement an exponential backoff retry ladder for transient failures
(httpx.TransportError, HTTP 5xx, HTTP 429). After retry_max attempts the
channel raises NotificationFailed. The CALLER (notifier.py) decides what to
record — channels are transport-only and do not write to the database.

4xx responses (non-429): no retry. A 400/401/403 indicates a configuration
defect (wrong bot token, bad API key, invalid chat_id). Retrying against a
misconfigured credential is noise. The exception message identifies the defect
class only — tokens and keys are NEVER included in exception messages or logs.

429 with Retry-After: the header value is respected as the sleep duration,
capped at backoff_base * 2^attempt to prevent runaway waits on malformed
headers.

==============================================================================
TASK 70 HANDOFF NOTE (SEV ESCALATION TRANSPORT)
==============================================================================
TelegramChannel.send() is the transport that Task 70's SEV alert router will
reuse directly. Task 70 constructs a TelegramChannel from settings
(same retry/record discipline) and calls send() with SEV-formatted text.
The channel is stateless — constructing multiple instances for different
purposes (hold alerts, SEV escalations) is safe and intentional.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from typing import Any

import httpx

from fluxpay.shared.logging import get_logger

__all__ = [
    "EmailChannel",
    "NotificationFailed",
    "TelegramChannel",
]

logger = get_logger("fluxpay.notifications.channels")

_DEFAULT_SLEEP: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep


class NotificationFailed(Exception):  # noqa: N818
    """Raised when a notification channel exhausts all retry attempts.

    Message contains only the defect class (e.g. 'transport_error', 'http_5xx').
    Credentials, tokens, and API keys are NEVER included.
    """


class TelegramChannel:
    """Async Telegram Bot API transport with exponential backoff retry.

    WHY NO MODULE-LEVEL CLIENT: httpx.AsyncClient carries connection pools
    and transport state. Module-level clients are reused across tests and
    processes in unpredictable ways. Every TelegramChannel instance receives
    its own injected client — MockTransport tests substitute a non-network
    client without patching global state.

    WHY PLAINTEXT (parse_mode omitted): See module docstring.
    WHY TOKEN NEVER LOGGED: bot_token is stored only in self._token (never
    logged, never included in exception strings). The token is used only in
    the URL path — a private attribute not exposed via __repr__ or __str__.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        bot_token: str,
        chat_id: str,
        retry_max: int,
        backoff_base_s: float,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Coroutine[Any, Any, None]] = _DEFAULT_SLEEP,
    ) -> None:
        self._client = http_client
        self._token = bot_token  # private; never in repr/logs/exceptions
        self._chat_id = chat_id
        self._retry_max = retry_max
        self._backoff_base = backoff_base_s
        self._now = now
        self._sleep = sleep

    @property
    def chat_id(self) -> str:
        """Public read-only accessor for the configured chat_id.

        Exposed so TelegramAdminNotifier can use the chat_id as the 'subject'
        field in notification_failures rows without accessing the private attribute.
        The bot token is still strictly private and never exposed.
        """
        return self._chat_id

    async def send(self, text: str) -> None:
        """POST message to Telegram Bot API with retry ladder.

        Raises:
            NotificationFailed: after retry_max attempts on transient errors.
        The exception message is defect-class only; tokens are never included.
        """
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        body = {
            "chat_id": self._chat_id,
            "text": text,
            # parse_mode deliberately omitted — see module docstring
        }

        last_exc: Exception | None = None
        for attempt in range(self._retry_max):
            try:
                response = await self._client.post(url, json=body, timeout=10.0)
            except httpx.TransportError as exc:
                last_exc = exc
                sleep_s = self._backoff_base * (2**attempt)
                logger.warning(
                    "telegram_transport_error",
                    attempt=attempt + 1,
                    retry_max=self._retry_max,
                    sleep_s=sleep_s,
                )
                await self._sleep(sleep_s)
                continue

            if response.status_code == 200:
                return  # success

            if response.status_code == 429:
                # Respect Retry-After header; cap at backoff ladder value
                retry_after_raw = response.headers.get("Retry-After", "")
                try:
                    retry_after = float(retry_after_raw)
                except (ValueError, TypeError):
                    retry_after = self._backoff_base * (2**attempt)
                sleep_s = min(retry_after, self._backoff_base * (2**attempt))
                logger.warning(
                    "telegram_rate_limited",
                    attempt=attempt + 1,
                    sleep_s=sleep_s,
                )
                last_exc = RuntimeError(f"http_429 attempt={attempt + 1}")
                await self._sleep(sleep_s)
                continue

            if response.status_code >= 500:
                sleep_s = self._backoff_base * (2**attempt)
                logger.warning(
                    "telegram_server_error",
                    status=response.status_code,
                    attempt=attempt + 1,
                    sleep_s=sleep_s,
                )
                last_exc = RuntimeError(f"http_5xx status={response.status_code}")
                await self._sleep(sleep_s)
                continue

            # 4xx non-429: configuration defect — do NOT retry
            # Message is defect-class only; token is NOT included
            logger.error(
                "telegram_client_error_no_retry",
                status=response.status_code,
                defect_class="http_4xx_config_error",
            )
            raise NotificationFailed(
                f"telegram_client_error status={response.status_code} defect_class=http_4xx"
            )

        raise NotificationFailed(
            f"telegram_exhausted_retries after {self._retry_max} attempts: "
            f"{type(last_exc).__name__}"
        )


class EmailChannel:
    """Async SendGrid v3 email transport with exponential backoff retry.

    WHY TEXT/PLAIN: payment notification emails are operational notices, not
    marketing. HTML email introduces tracking pixels, phishing-style formatting,
    and rendering inconsistencies across email clients. Plain text is
    unambiguous and universally supported. See module docstring.

    WHY 202 = SUCCESS: SendGrid v3 /mail/send returns HTTP 202 Accepted on
    success. The message is queued for delivery; 200 is NOT returned.

    WHY NO API KEY IN EXCEPTIONS: api_key stored as a private attribute,
    never in logs, repr, or exception messages.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        api_key: str,
        from_addr: str,
        retry_max: int,
        backoff_base_s: float,
        sleep: Callable[[float], Coroutine[Any, Any, None]] = _DEFAULT_SLEEP,
    ) -> None:
        self._client = http_client
        self._api_key = api_key  # private; never in repr/logs/exceptions
        self._from_addr = from_addr
        self._retry_max = retry_max
        self._backoff_base = backoff_base_s
        self._sleep = sleep

    async def send(self, *, to_email: str, subject: str, body: str) -> None:
        """POST email via SendGrid v3 /mail/send with retry ladder.

        Content is sent as text/plain (see module docstring).
        202 = SendGrid success (queued for delivery).

        Raises:
            NotificationFailed: after retry_max attempts on transient errors.
        API key is NEVER included in exceptions.
        """
        url = "https://api.sendgrid.com/v3/mail/send"
        payload = {
            "personalizations": [{"to": [{"email": to_email}]}],
            "from": {"email": self._from_addr},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}],
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        last_exc: Exception | None = None
        for attempt in range(self._retry_max):
            try:
                response = await self._client.post(url, json=payload, headers=headers, timeout=10.0)
            except httpx.TransportError as exc:
                last_exc = exc
                sleep_s = self._backoff_base * (2**attempt)
                logger.warning(
                    "email_transport_error",
                    attempt=attempt + 1,
                    retry_max=self._retry_max,
                    sleep_s=sleep_s,
                )
                await self._sleep(sleep_s)
                continue

            if response.status_code == 202:
                return  # SendGrid success

            if response.status_code >= 500:
                sleep_s = self._backoff_base * (2**attempt)
                logger.warning(
                    "email_server_error",
                    status=response.status_code,
                    attempt=attempt + 1,
                    sleep_s=sleep_s,
                )
                last_exc = RuntimeError(f"http_5xx status={response.status_code}")
                await self._sleep(sleep_s)
                continue

            # 4xx (including 400 bad request, 401 unauthorized): config defect — no retry
            # API key is NOT included in the message
            logger.error(
                "email_client_error_no_retry",
                status=response.status_code,
                defect_class="http_4xx_config_error",
            )
            raise NotificationFailed(
                f"email_client_error status={response.status_code} defect_class=http_4xx"
            )

        raise NotificationFailed(
            f"email_exhausted_retries after {self._retry_max} attempts: {type(last_exc).__name__}"
        )
