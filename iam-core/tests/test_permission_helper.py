import sys
from pathlib import Path

from iam_core.user_auth.dependencies import enforce_resource_access
from iam_core.user_auth.helpers.permission_helper import (
    get_required_permissions,
    require_permissions,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
STAFF_PORTAL_SRC = REPO_ROOT / "openg2p-registry-gen2-apis" / "openg2p-registry-staff-portal-api" / "src"
if str(STAFF_PORTAL_SRC) not in sys.path:
    sys.path.append(str(STAFF_PORTAL_SRC))

from openg2p_registry_staff_portal_api.controllers.g2p_intake_form_metadata_controller import (  # noqa: E402
    G2PIntakeFormMetadataController,
)
from openg2p_registry_staff_portal_api.controllers.g2p_registry_configuration_controller import (  # noqa: E402
    G2PRegistryConfigurationController,
)


def test_require_permissions_accepts_varargs():
    @require_permissions("one", "two")
    def endpoint():
        return None

    assert get_required_permissions(endpoint) == {"one", "two"}


def test_require_permissions_accepts_set_and_normalizes_values():
    @require_permissions({" one ", "", "two"})
    def endpoint():
        return None

    assert get_required_permissions(endpoint) == {"one", "two"}


def test_enforce_resource_access_uses_or_semantics_for_multiple_permissions():
    auth = {"client_roles": {"staff-portal": ["changeRequest:view"]}}

    result = enforce_resource_access(
        auth=auth,
        allowed_roles={"registryConfiguration:view", "changeRequest:view"},
        client_id="staff-portal",
    )

    assert result is auth


def test_staff_portal_single_permission_metadata_is_set():
    assert get_required_permissions(G2PIntakeFormMetadataController.get_intake_form) == {
        "intakeForm:view"
    }


def test_staff_portal_multi_permission_metadata_is_set():
    assert get_required_permissions(
        G2PRegistryConfigurationController.get_number_of_requests_pending
    ) == {"registryConfiguration:view", "changeRequest:view"}
