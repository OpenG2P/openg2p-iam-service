from datetime import datetime

from fastapi import Request
from openg2p_fastapi_common.errors.base_exception import BaseAppException
from openg2p_fastapi_common.schemas import (
    G2PResponse,
    G2PResponseBody,
    G2PResponseHeader,
    G2PResponseStatus,
)
from starlette.responses import JSONResponse


def user_auth_error_response(request: Request, exc: BaseAppException) -> JSONResponse:
    """Construct a standard G2P envelope for middleware-layer auth failures."""
    request_id = request.headers.get("x-request-id", "")

    response = G2PResponse(
        response_header=G2PResponseHeader(
            request_id=request_id,
            response_status=G2PResponseStatus.ERROR,
            response_error_code=str(getattr(exc, "code", exc.status_code)),
            response_error_message=str(exc.message),
            response_timestamp=datetime.now(),
        ),
        response_body=G2PResponseBody(
            pagination_response=None,
            response_payload=None,
        ),
    )
    return JSONResponse(content=response.model_dump(mode="json"), status_code=exc.status_code)
