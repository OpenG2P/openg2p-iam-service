from openg2p_fastapi_common.errors.http_exceptions import BadRequestError


def handle_exception(e, message_prefix="Error"):
    """Helper function to raise BadRequestError with a formatted message."""
    raise BadRequestError(message=f"{message_prefix}: {str(e)}") from None
