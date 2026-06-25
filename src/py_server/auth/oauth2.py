"""OAuth2 хранилище и сервис для авторизации."""

import hashlib
import base64
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple
from urllib.parse import urlencode

from .store_base import (
	OAuth2StoreBase,
	AuthCodeData,
	AccessTokenData,
	RefreshTokenData,
	ClientData,
)

logger = logging.getLogger(__name__)


class InMemoryOAuth2Store(OAuth2StoreBase):
	"""In-memory хранилище для OAuth2 токенов, кодов и клиентов."""

	def __init__(self):
		"""Инициализация хранилища."""
		super().__init__()
		self.auth_codes: dict[str, AuthCodeData] = {}
		self.access_tokens: dict[str, AccessTokenData] = {}
		self.refresh_tokens: dict[str, RefreshTokenData] = {}
		self.clients: dict[str, ClientData] = {}

	async def cleanup_expired(self) -> None:
		"""Удалить устаревшие токены и коды."""
		now = datetime.now()

		expired_codes = [code for code, data in self.auth_codes.items() if data.exp < now]
		for code in expired_codes:
			del self.auth_codes[code]

		expired_access = [token for token, data in self.access_tokens.items() if data.exp < now]
		for token in expired_access:
			del self.access_tokens[token]

		expired_refresh = [token for token, data in self.refresh_tokens.items() if data.exp < now]
		for token in expired_refresh:
			del self.refresh_tokens[token]

		if expired_codes or expired_access or expired_refresh:
			logger.debug(
				f"Очищено токенов: codes={len(expired_codes)}, "
				f"access={len(expired_access)}, refresh={len(expired_refresh)}"
			)

	# ── Authorization Codes ──

	async def save_auth_code(self, code: str, data: AuthCodeData) -> None:
		"""Сохранить authorization code."""
		self.auth_codes[code] = data
		logger.debug(f"Сохранён authorization code для {data.login}, expires в {data.exp}")

	async def get_auth_code(self, code: str) -> Optional[AuthCodeData]:
		"""Получить и удалить authorization code (одноразовый)."""
		data = self.auth_codes.pop(code, None)
		if data and data.exp < datetime.now():
			logger.debug(f"Authorization code истёк: {code}")
			return None
		return data

	# ── Access Tokens ──

	async def save_access_token(self, token: str, data: AccessTokenData) -> None:
		"""Сохранить access token."""
		self.access_tokens[token] = data
		logger.debug(f"Сохранён access token для {data.login}, expires в {data.exp}")

	async def get_access_token(self, token: str) -> Optional[AccessTokenData]:
		"""Получить access token."""
		data = self.access_tokens.get(token)
		if data and data.exp < datetime.now():
			logger.debug(f"Access token истёк: {token[:16]}...")
			del self.access_tokens[token]
			return None
		return data

	async def delete_access_token(self, token: str) -> None:
		"""Удалить access token."""
		self.access_tokens.pop(token, None)

	# ── Refresh Tokens ──

	async def save_refresh_token(self, token: str, data: RefreshTokenData) -> None:
		"""Сохранить refresh token."""
		self.refresh_tokens[token] = data
		logger.debug(f"Сохранён refresh token для {data.login}, expires в {data.exp}")

	async def get_refresh_token(self, token: str) -> Optional[RefreshTokenData]:
		"""Получить и удалить refresh token (ротация)."""
		data = self.refresh_tokens.pop(token, None)
		if data and data.exp < datetime.now():
			logger.debug(f"Refresh token истёк: {token[:16]}...")
			return None
		return data

	async def delete_refresh_token(self, token: str) -> None:
		"""Удалить refresh token."""
		self.refresh_tokens.pop(token, None)

	# ── Clients ──

	async def save_client(self, client_id: str, data: ClientData) -> None:
		"""Сохранить данные клиента."""
		self.clients[client_id] = data
		logger.debug(f"Сохранён клиент {client_id}")

	async def get_client(self, client_id: str) -> Optional[ClientData]:
		"""Получить данные клиента по client_id."""
		return self.clients.get(client_id)


# Alias для обратной совместимости
OAuth2Store = InMemoryOAuth2Store


class OAuth2Service:
	"""Сервис OAuth2 для авторизации."""

	DEFAULT_REDIRECT_URIS = frozenset({
		"http://localhost/callback",
		"http://127.0.0.1/callback",
	})

	def __init__(
		self,
		store: OAuth2StoreBase,
		code_ttl: int = 120,
		access_ttl: int = 3600,
		refresh_ttl: int = 1209600,
	):
		"""Инициализация сервиса.

		Args:
			store: Хранилище токенов (in-memory или персистентное)
			code_ttl: TTL authorization code в секундах
			access_ttl: TTL access token в секундах
			refresh_ttl: TTL refresh token в секундах
		"""
		self.store = store
		self.code_ttl = code_ttl
		self.access_ttl = access_ttl
		self.refresh_ttl = refresh_ttl

	# ── Metadata ──

	def generate_prm_document(self, public_url: str) -> dict:
		"""Сгенерировать Protected Resource Metadata документ (RFC 9728)."""
		public_url = public_url.rstrip('/')
		return {
			"resource": public_url,
			"authorization_servers": [public_url],
			"authorization_endpoint": f"{public_url}/authorize",
			"token_endpoint": f"{public_url}/token",
			"code_challenge_methods_supported": ["S256"],
		}

	# ── Client Registration ──

	async def register_client(
		self,
		redirect_uris: list[str],
		client_name: Optional[str] = None,
	) -> ClientData:
		"""Зарегистрировать новый OAuth2 клиент (RFC 7591).

		Args:
			redirect_uris: Список разрешённых redirect URIs
			client_name: Опциональное имя клиента

		Returns:
			Данные зарегистрированного клиента
		"""
		# Дедупликация URI с сохранением порядка
		unique_uris = list(dict.fromkeys(uri for uri in redirect_uris if uri))

		# Генерируем уникальный client_id
		client_id = f"mcp_{secrets.token_urlsafe(16)}"
		client_data = ClientData(
			client_id=client_id,
			client_secret="",
			redirect_uris=unique_uris,
			grant_types=["authorization_code", "refresh_token", "password"],
			response_types=["code"],
			token_endpoint_auth_method="none",
			application_type="web",
			client_id_issued_at=datetime.now().timestamp(),
			client_name=client_name,
		)

		await self.store.save_client(client_id, client_data)
		logger.info(f"Зарегистрирован клиент {client_id}, redirect_uris={unique_uris}")

		return client_data

	async def is_redirect_uri_valid(self, client_id: str, redirect_uri: str) -> bool:
		"""Проверить, что redirect_uri разрешён для клиента.

		Проверяет:
		1. Default URIs (localhost) — всегда разрешены
		2. Зарегистрированные URIs конкретного клиента

		Args:
			client_id: Идентификатор клиента
			redirect_uri: URI для проверки

		Returns:
			True если URI разрешён
		"""
		if redirect_uri in self.DEFAULT_REDIRECT_URIS:
			return True

		client = await self.store.get_client(client_id)
		if client and redirect_uri in client.redirect_uris:
			return True

		return False

	# ── Authorization Code Flow ──

	async def generate_authorization_code(
		self,
		login: str,
		password: str,
		redirect_uri: str,
		code_challenge: str,
	) -> str:
		"""Сгенерировать authorization code."""
		code = secrets.token_urlsafe(32)
		exp = datetime.now() + timedelta(seconds=self.code_ttl)

		await self.store.save_auth_code(code, AuthCodeData(
			login=login,
			password=password,
			redirect_uri=redirect_uri,
			code_challenge=code_challenge,
			exp=exp,
		))

		return code

	def validate_pkce(self, code_verifier: str, code_challenge: str) -> bool:
		"""Валидировать PKCE S256."""
		verifier_hash = hashlib.sha256(code_verifier.encode('ascii')).digest()
		computed_challenge = base64.urlsafe_b64encode(verifier_hash).decode('ascii').rstrip('=')
		return computed_challenge == code_challenge

	async def exchange_code_for_tokens(
		self,
		code: str,
		redirect_uri: str,
		code_verifier: str,
	) -> Optional[Tuple[str, str, int, str]]:
		"""Обменять authorization code на токены.

		Returns:
			Tuple (access_token, token_type, expires_in, refresh_token) или None
		"""
		code_data = await self.store.get_auth_code(code)
		if not code_data:
			logger.warning("Недействительный или истёкший authorization code")
			return None

		if code_data.redirect_uri != redirect_uri:
			logger.warning(
				f"Несовпадение redirect_uri: ожидался {code_data.redirect_uri}, "
				f"получен {redirect_uri}"
			)
			return None

		if not self.validate_pkce(code_verifier, code_data.code_challenge):
			logger.warning("PKCE валидация не прошла")
			return None

		access_token = secrets.token_urlsafe(32)
		refresh_token = secrets.token_urlsafe(32)

		access_exp = datetime.now() + timedelta(seconds=self.access_ttl)
		refresh_exp = datetime.now() + timedelta(seconds=self.refresh_ttl)

		await self.store.save_access_token(access_token, AccessTokenData(
			login=code_data.login,
			password=code_data.password,
			exp=access_exp,
		))

		await self.store.save_refresh_token(refresh_token, RefreshTokenData(
			login=code_data.login,
			password=code_data.password,
			exp=refresh_exp,
			rotation_counter=0,
		))

		logger.debug(f"Выданы токены для пользователя {code_data.login}")
		return (access_token, "Bearer", self.access_ttl, refresh_token)

	async def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str, int, str]]:
		"""Обновить токены по refresh token.

		Returns:
			Tuple (access_token, token_type, expires_in, new_refresh_token) или None
		"""
		refresh_data = await self.store.get_refresh_token(refresh_token)
		if not refresh_data:
			logger.warning("Недействительный или истёкший refresh token")
			return None

		new_access_token = secrets.token_urlsafe(32)
		new_refresh_token = secrets.token_urlsafe(32)

		access_exp = datetime.now() + timedelta(seconds=self.access_ttl)
		refresh_exp = datetime.now() + timedelta(seconds=self.refresh_ttl)

		await self.store.save_access_token(new_access_token, AccessTokenData(
			login=refresh_data.login,
			password=refresh_data.password,
			exp=access_exp,
		))

		await self.store.save_refresh_token(new_refresh_token, RefreshTokenData(
			login=refresh_data.login,
			password=refresh_data.password,
			exp=refresh_exp,
			rotation_counter=refresh_data.rotation_counter + 1,
		))

		logger.debug(
			f"Обновлены токены для пользователя {refresh_data.login} "
			f"(rotation #{refresh_data.rotation_counter + 1})"
		)
		return (new_access_token, "Bearer", self.access_ttl, new_refresh_token)

	async def validate_access_token(self, token: str) -> Optional[Tuple[str, str]]:
		"""Валидировать access token и получить креды 1С.

		Returns:
			Tuple (login, password) или None
		"""
		token_data = await self.store.get_access_token(token)
		if not token_data:
			return None

		return (token_data.login, token_data.password)
