"""Базовые модели данных и абстрактное хранилище для OAuth2."""

import abc
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)


# ──────────────────────────── Data Models ────────────────────────────

@dataclass
class AuthCodeData:
	"""Данные authorization code."""
	login: str
	password: str
	redirect_uri: str
	code_challenge: str
	exp: datetime


@dataclass
class AccessTokenData:
	"""Данные access token."""
	login: str
	password: str
	exp: datetime


@dataclass
class RefreshTokenData:
	"""Данные refresh token."""
	login: str
	password: str
	exp: datetime
	rotation_counter: int = 0


@dataclass
class ClientData:
	"""Данные зарегистрированного OAuth2 клиента (RFC 7591)."""
	client_id: str
	client_secret: str = ""
	redirect_uris: List[str] = field(default_factory=list)
	grant_types: List[str] = field(default_factory=lambda: ["authorization_code", "refresh_token", "password"])
	response_types: List[str] = field(default_factory=lambda: ["code"])
	token_endpoint_auth_method: str = "none"
	application_type: str = "web"
	client_id_issued_at: int = 0
	client_name: Optional[str] = None

	def to_dict(self) -> dict:
		"""Сериализация в dict для JSON-ответа /rregister."""
		return {
			"client_id": self.client_id,
			"client_secret": self.client_secret,
			"client_id_issued_at": self.client_id_issued_at,
			"grant_types": self.grant_types,
			"response_types": self.response_types,
			"redirect_uris": self.redirect_uris,
			"token_endpoint_auth_method": self.token_endpoint_auth_method,
			"application_type": self.application_type,
			**({"client_name": self.client_name} if self.client_name else {}),
		}


# ──────────────────────────── Abstract Store ────────────────────────────

class OAuth2StoreBase(abc.ABC):
	"""Абстрактный интерфейс хранилища OAuth2.

	Реализации: InMemoryOAuth2Store (RAM), SqliteOAuth2Store (персистентный).
	"""

	def __init__(self):
		"""Инициализация хранилища."""
		self._cleanup_task: Optional[asyncio.Task] = None

	# ── Lifecycle ──

	async def initialize(self) -> None:
		"""Асинхронная инициализация (создание таблиц, подключение к БД).

		Переопределяется в персистентных реализациях.
		По умолчанию — no-op для in-memory.
		"""
		pass

	async def close(self) -> None:
		"""Закрытие соединений при остановке.

		Переопределяется в персистентных реализациях.
		"""
		pass

	async def start_cleanup_task(self, interval: int = 60) -> None:
		"""Запустить периодическую очистку устаревших токенов."""
		self._cleanup_task = asyncio.create_task(self._cleanup_loop(interval))
		logger.debug(f"Запущена задача очистки OAuth2 токенов (интервал: {interval}s)")

	async def stop_cleanup_task(self) -> None:
		"""Остановить задачу очистки."""
		if self._cleanup_task:
			self._cleanup_task.cancel()
			try:
				await self._cleanup_task
			except asyncio.CancelledError:
				pass
			logger.debug("Задача очистки OAuth2 токенов остановлена")

	async def _cleanup_loop(self, interval: int) -> None:
		"""Периодическая очистка устаревших токенов."""
		while True:
			try:
				await asyncio.sleep(interval)
				await self.cleanup_expired()
			except asyncio.CancelledError:
				break
			except Exception as e:
				logger.error(f"Ошибка при очистке токенов: {e}")

	async def cleanup_expired(self) -> None:
		"""Удалить устаревшие токены и коды.

		Реализация по умолчанию вызывает синхронный метод.
		"""
		pass

	# ── Authorization Codes (короткоживущие, одноразовые) ──

	@abc.abstractmethod
	async def save_auth_code(self, code: str, data: AuthCodeData) -> None:
		"""Сохранить authorization code."""
		...

	@abc.abstractmethod
	async def get_auth_code(self, code: str) -> Optional[AuthCodeData]:
		"""Получить и удалить authorization code (одноразовый)."""
		...

	# ── Access Tokens ──

	@abc.abstractmethod
	async def save_access_token(self, token: str, data: AccessTokenData) -> None:
		"""Сохранить access token."""
		...

	@abc.abstractmethod
	async def get_access_token(self, token: str) -> Optional[AccessTokenData]:
		"""Получить access token (проверяет TTL)."""
		...

	@abc.abstractmethod
	async def delete_access_token(self, token: str) -> None:
		"""Удалить access token (для revoke)."""
		...

	# ── Refresh Tokens ──

	@abc.abstractmethod
	async def save_refresh_token(self, token: str, data: RefreshTokenData) -> None:
		"""Сохранить refresh token."""
		...

	@abc.abstractmethod
	async def get_refresh_token(self, token: str) -> Optional[RefreshTokenData]:
		"""Получить и удалить refresh token (ротация)."""
		...

	@abc.abstractmethod
	async def delete_refresh_token(self, token: str) -> None:
		"""Удалить refresh token (для revoke)."""
		...

	# ── Clients (постоянные данные) ──

	@abc.abstractmethod
	async def save_client(self, client_id: str, data: ClientData) -> None:
		"""Сохранить данные клиента."""
		...

	@abc.abstractmethod
	async def get_client(self, client_id: str) -> Optional[ClientData]:
		"""Получить данные клиента по client_id."""
		...
