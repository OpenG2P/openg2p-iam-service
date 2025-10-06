from datetime import datetime
from typing import Optional


def create_user_process_gender(gender: Optional[str]) -> Optional[str]:
    return gender.capitalize() if gender else None


def create_user_process_birthdate(
    birthdate: Optional[str], date_format: str = "%Y/%m/%d"
) -> Optional[datetime.date]:
    if not birthdate:
        return None
    return datetime.strptime(birthdate, date_format).date()
