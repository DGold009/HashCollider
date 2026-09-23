"""Persistent storage of collision records (JSON).

Future backends (CSV, SQLite, ...) can be added next to :mod:`.collisions`
as long as they round-trip :class:`~hashcollider.collision.CollisionResult`.
"""

from __future__ import annotations

from .collisions import collision_to_json, load_collision, save_collision

__all__ = ["collision_to_json", "load_collision", "save_collision"]
