"""SQLite-персистентное хранилище OAuth2 данных."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiosqlite

from .store_base import (
	OAuth2StoreBase,
	AuthCodeData,
	AccessTokenData,
	RefreshTokenData,
	ClientData,
)

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS access_tokens (
	token       TEXT PRIMARY KEY,
	login       TEXT NOT NULL,
	password    TEXT NOT NULL,
	exp         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	token            TEXT PRIMARY KEY,
	login            TEXT NOT NULL,
	password         TEXT NOT NULL,
	exp              TEXT NOT NULL,
	rotation_counter INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clients (
	client_id                  TEXT PRIMARY KEY,
	client_secret              TEXT NOT NULL DEFAULT '',
	grant_types                TEXT NOT NULL,
	response_types             TEXT NOT NULL,
	token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
	application_type           TEXT NOT NULL DEFAULT 'web',
	client_id_issued_at        REAL NOT NULL,
	client_name                TEXT
);

CREATE TABLE IF NOT EXISTS client_redirect_uris (
	client_id    TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	PRIMARY KEY (client_id, redirect_uri),
	FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);
"""


class SqliteOAuth2Store(OAuth2StoreBase):
	"""Персистентное хранилище OAuth2 на SQLite.

	Access tokens, refresh tokens и клиенты сохраняются на диск.
	Authorization codes остаются в RAM (короткоживущие, одноразовые).
	"""

	def __init__(self, db_path: str):
		"""Инициализация.

		Args:
			db_path: Путь к файлу SQLite
		"""
		super().__init__()
		self._db_path = db_path
		self._db: Optional[aiosqlite.Connection] = None
		# Authorization codes — только в RAM
		self._auth_codes: dict[str, AuthCodeData] = {}

	# ── Lifecycle ──

	async def initialize(self) -> None:
		"""Создать подключение и таблицы."""
		db_dir = Path(self._db_path).parent
		db_dir.mkdir(parents=True, exist_ok=True)

		self._db = await aiosqlite.connect(self._db_path)
		self._db.row_factory = aiosqlite.Row

		await self._db.execute("PRAGMA journal_mode=WAL")
		await self._db.execute("PRAGMA foreign_keys=ON")
		await self._db.execute("PRAGMA synchronous=NORMAL")

		await self._db.executescript(_SCHEMA)
		await self._db.commit()

		logger.info(f"SQLite OAuth2 хранилище инициализировано: {self._db_path}")

	async def close(self) -> None:
		"""Закрыть подключение к БД."""
		if self._db:
			await self._db.close()
			self._db = None
			logger.debug("Подключение к SQLite закрыто")

	# ── Helpers ──

	@staticmethod
	def _row_to_access_token(row: aiosqlite.Row) -> AccessTokenData:
		return AccessTokenData(
			login=row["login"],
			password=row["password"],
			exp=datetime.fromisoformat(row["exp"]),
		)

	@staticmethod
	def _row_to_refresh_token(row: aiosqlite.Row) -> RefreshTokenData:
		return RefreshTokenData(
			login=row["login"],
			password=row["password"],
			exp=datetime.fromisoformat(row["exp"]),
			rotation_counter=row["rotation_counter"],
		)

	async def _row_to_client(self, row: aiosqlite.Row) -> ClientData:
		"""Собрать ClientData из строки + связанных redirect_uris."""
		async with self._db.execute(
			"SELECT redirect_uri FROM client_redirect_uris WHERE client_id = ? ORDER BY redirect_uri",
			(row["client_id"],),
		) as cur:
			uri_rows = await cur.fetchall()

		return ClientData(
			client_id=row["client_id"],
			client_secret=row["client_secret"],
			redirect_uris=[r["redirect_uri"] for r in uri_rows],
			grant_types=json.loads(row["grant_types"]),
			response_types=json.loads(row["response_types"]),
			token_endpoint_auth_method=row["token_endpoint_auth_method"],
			application_type=row["application_type"],
			client_id_issued_at=row["client_id_issued_at"],
			client_name=row["client_name"],
		)

	# ── Cleanup ──

	async def cleanup_expired(self) -> None:
		"""Удалить устаревшие токены (access, refresh) из SQLite и auth codes из RAM."""
		now_iso = datetime.now().isoformat()

		# Access tokens
		cursor = await self._db.execute(
			"DELETE FROM access_tokens WHERE exp < ?", (now_iso,)
		)
		expired_access = cursor.rowcount
		await self._db.commit()

		# Refresh tokens
		cursor = await self._db.execute(
			"DELETE FROM refresh_tokens WHERE exp < ?", (now_iso,)
		)
		expired_refresh = cursor.rowcount
		await self._db.commit()

		# Auth codes (RAM)
		now = datetime.now()
		expired_codes = [c for c, d in self._auth_codes.items() if d.exp < now]
		for code in expired_codes:
			del self._auth_codes[code]

		if expired_codes or expired_access or expired_refresh:
			logger.debug(
				f"Очищено токенов: codes={len(expired_codes)}, "
				f"access={expired_access}, refresh={expired_refresh}"
			)

	# ── Authorization Codes (RAM only) ──

	async def save_auth_code(self, code: str, data: AuthCodeData) -> None:
		"""Сохранить authorization code в RAM."""
		self._auth_codes[code] = data
		logger.debug(f"Сохранён authorization code для {data.login}, expires в {data.exp}")

	async def get_auth_code(self, code: str) -> Optional[AuthCodeData]:
		"""Получить и удалить authorization code (одноразовый)."""
		data = self._auth_codes.pop(code, None)
		if data and data.exp < datetime.now():
			logger.debug(f"Authorization code истёк: {code}")
			return None
		return data

	# ── Access Tokens (SQLite) ──

	async def save_access_token(self, token: str, data: AccessTokenData) -> None:
		"""Сохранить access token."""
		await self._db.execute(
			"INSERT OR REPLACE INTO access_tokens (token, login, password, exp) VALUES (?, ?, ?, ?)",
			(token, data.login, data.password, data.exp.isoformat()),
		)
		await self._db.commit()
		logger.debug(f"Сохранён access token для {data.login}, expires в {data.exp}")

	async def get_access_token(self, token: str) -> Optional[AccessTokenData]:
		"""Получить access token (проверяет TTL)."""
		now_iso = datetime.now().isoformat()
		async with self._db.execute(
			"SELECT login, password, exp FROM access_tokens WHERE token = ? AND exp > ?",
			(token, now_iso),
		) as cur:
			row = await cur.fetchone()

		if not row:
			return None
		return self._row_to_access_token(row)

	async def delete_access_token(self, token: str) -> None:
		"""Удалить access token."""
		await self._db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
		await self._db.commit()

	# ── Refresh Tokens (SQLite) ──

	async def save_refresh_token(self, token: str, data: RefreshTokenData) -> None:
		"""Сохранить refresh token."""
		await self._db.execute(
			"""INSERT OR REPLACE INTO refresh_tokens
			   (token, login, password, exp, rotation_counter)
			   VALUES (?, ?, ?, ?, ?)""",
			(token, data.login, data.password, data.exp.isoformat(), data.rotation_counter),
		)
		await self._db.commit()
		logger.debug(f"Сохранён refresh token для {data.login}, expires в {data.exp}")

	async def get_refresh_token(self, token: str) -> Optional[RefreshTokenData]:
		"""Получить и удалить refresh token (ротация).

		Использует DELETE ... RETURNING для атомарного read+delete.
		"""
		now_iso = datetime.now().isoformat()
		async with self._db.execute(
			"""DELETE FROM refresh_tokens
			   WHERE token = ? AND exp > ?
			   RETURNING login, password, exp, rotation_counter""",
			(token, now_iso),
		) as cur:
			row = await cur.fetchone()

		await self._db.commit()

		if not row:
			logger.debug(f"Refresh token не найден или истёк: {token[:16]}...")
			return None
		return self._row_to_refresh_token(row)

	async def delete_refresh_token(self, token: str) -> None:
		"""Удалить refresh token."""
		await self._db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
		await self._db.commit()

	# ── Clients (SQLite) ──

	async def save_client(self, client_id: str, data: ClientData) -> None:
		"""Сохранить данные клиента."""
		await self._db.execute(
			"""INSERT OR REPLACE INTO clients
			   (client_id, client_secret, grant_types, response_types,
			    token_endpoint_auth_method, application_type,
			    client_id_issued_at, client_name)
			   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
			(
				data.client_id,
				data.client_secret,
				json.dumps(data.grant_types),
				json.dumps(data.response_types),
				data.token_endpoint_auth_method,
				data.application_type,
				data.client_id_issued_at,
				data.client_name,
			),
		)

		# Перезаписываем redirect_uris
		await self._db.execute(
			"DELETE FROM client_redirect_uris WHERE client_id = ?",
			(client_id,),
		)
		if data.redirect_uris:
			await self._db.executemany(
				"INSERT OR IGNORE INTO client_redirect_uris (client_id, redirect_uri) VALUES (?, ?)",
				[(client_id, uri) for uri in data.redirect_uris],
			)

		await self._db.commit()
		logger.debug(f"Сохранён клиент {client_id}")

	async def get_client(self, client_id: str) -> Optional[ClientData]:
		"""Получить данные клиента по client_id."""
		async with self._db.execute(
			"SELECT * FROM clients WHERE client_id = ?",
			(client_id,),
		) as cur:
			row = await cur.fetchone()

		if not row:
			return None
		return await self._row_to_client(row)
