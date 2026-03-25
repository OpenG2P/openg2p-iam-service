from collections.abc import Callable
from typing import Any

REQUIRED_ROLES_ATTR = "_required_roles"


def require_permissions(allowed_roles: set[str]):
	"""Attach required IAM roles to an endpoint for middleware enforcement."""
	normalized_roles = {role.strip() for role in allowed_roles if role and role.strip()}

	def decorator(func: Callable[..., Any]):
		setattr(func, REQUIRED_ROLES_ATTR, frozenset(normalized_roles))
		return func

	return decorator


def get_required_permissions(endpoint: Any) -> set[str]:
	"""Read required roles from endpoint metadata, handling bound methods."""
	if endpoint is None:
		return set()

	candidates = [endpoint]
	endpoint_func = getattr(endpoint, "__func__", None)
	if endpoint_func is not None:
		candidates.append(endpoint_func)

	for candidate in candidates:
		roles = getattr(candidate, REQUIRED_ROLES_ATTR, None)
		if roles:
			return {str(role) for role in roles}

	return set()
