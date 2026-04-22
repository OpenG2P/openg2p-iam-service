from collections.abc import Callable, Iterable
from typing import Any

REQUIRED_ROLES_ATTR = "_required_roles"


def _normalize_permissions(*allowed_roles: str | Iterable[str]) -> frozenset[str]:
	"""Normalize decorator inputs from varargs or a single iterable."""
	if len(allowed_roles) == 1 and not isinstance(allowed_roles[0], str):
		raw_roles = allowed_roles[0]
	else:
		raw_roles = allowed_roles

	return frozenset(
		str(role).strip()
		for role in raw_roles
		if role and str(role).strip()
	)


def require_permissions(*allowed_roles: str | Iterable[str]):
	"""Attach required IAM roles to an endpoint for middleware enforcement."""
	normalized_roles = _normalize_permissions(*allowed_roles)

	def decorator(func: Callable[..., Any]):
		setattr(func, REQUIRED_ROLES_ATTR, frozenset(normalized_roles))
		return func

	return decorator


def get_required_permissions(endpoint: Any) -> set[str] | None:
	"""Read required roles from endpoint metadata, handling bound methods."""
	if endpoint is None:
		return None

	candidates = [endpoint]
	endpoint_func = getattr(endpoint, "__func__", None)
	if endpoint_func is not None:
		candidates.append(endpoint_func)

	for candidate in candidates:
		if hasattr(candidate, REQUIRED_ROLES_ATTR):
			roles = getattr(candidate, REQUIRED_ROLES_ATTR)
			return {str(role) for role in roles}

	return None
