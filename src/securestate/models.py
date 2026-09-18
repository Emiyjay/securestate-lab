from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class AssessmentResult:
    check_id: str
    control: str
    platform: str
    status: CheckStatus
    summary: str
    evidence: str
    recommendation: str
    timestamp_utc: str

    @classmethod
    def create(
        cls,
        check_id: str,
        control: str,
        platform: str,
        status: CheckStatus,
        summary: str,
        evidence: str,
        recommendation: str
    ):
        return cls(
            check_id=check_id,
            control=control,
            platform=platform,
            status=status,
            summary=summary,
            evidence=evidence,
            recommendation=recommendation,
            timestamp_utc=datetime.now(timezone.utc).isoformat()
        )

    def to_dict(self):
        result = asdict(self)
        result["status"] = self.status.value
        return result