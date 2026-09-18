from securestate.models import AssessmentResult, CheckStatus


def evaluate_boolean_control(
    check_id: str,
    control: str,
    platform: str,
    observed_value: bool | None,
    expected_value: bool,
    evidence: str,
    recommendation: str,
    supported: bool = True
) -> AssessmentResult:

    if not supported:
        status = CheckStatus.NOT_APPLICABLE
        summary = "This security check is not applicable."

    elif observed_value is None:
        status = CheckStatus.UNKNOWN
        summary = "The security state could not be determined."

    elif observed_value == expected_value:
        status = CheckStatus.PASS
        summary = "The security control meets the defined criterion."

    else:
        status = CheckStatus.FAIL
        summary = "The security control does not meet the defined criterion."

    return AssessmentResult.create(
        check_id=check_id,
        control=control,
        platform=platform,
        status=status,
        summary=summary,
        evidence=evidence,
        recommendation=recommendation
    )