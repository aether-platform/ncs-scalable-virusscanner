from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ScanStatus(Enum):
    PENDING = "PENDING"
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"


@dataclass
class ScanResult:
    task_id: str
    status: ScanStatus
    virus_name: Optional[str] = None
    detail: Optional[str] = None

    def is_infected(self) -> bool:
        return self.status == ScanStatus.INFECTED
