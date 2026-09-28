"""Administrative plane hold voting endpoint (Task 42 - Block H, Part 4).

POST /admin/holds/{hold_id}/vote:
Orchestrates human governance 2-man authorization on quarantined payment holds.
Enforces admin-only privileges (support operators rejected with 403 ForbiddenError).
All audit logging executes inside submit_vote's UnitOfWork.
"""

from __future__ import annotations

from uuid import UUID

import orjson
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from fluxpay.approvals.service import ApprovalService
from fluxpay.shared.errors import AuthenticationError, ForbiddenError, ValidationError

__all__ = ["router", "vote_hold"]

router = APIRouter()


@router.post("/admin/holds/{hold_id}/vote")
async def vote_hold(hold_id: UUID, request: Request) -> JSONResponse:
    """Submit an approval or rejection vote on a quarantined payment hold.

    Role Requirement: 'admin' only.
    Request Body:
        {"vote": "approve" | "reject", "note": "optional justification"}
    Response (200 OK):
        {"status": "counted" | "approved_settled" | "rejected" | "already_voted",
         "votes_for": int, "votes_against": int}
    """
    # 1. Identity & Role Verification (AdminAuthMiddleware sets principal)
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise AuthenticationError(message="Authentication credentials were missing or invalid.")

    if principal.role != "admin":
        raise ForbiddenError(message="insufficient permissions: admin role required to vote")

    # 2. Request body extraction & validation
    try:
        raw_body = await request.body()
        if not raw_body:
            raise ValidationError(message="Request payload failed validation.")
        data = orjson.loads(raw_body)
    except Exception as exc:
        raise ValidationError(
            message="Request payload failed validation.",
            details={"reason": "malformed_json", "error": str(exc)},
        ) from exc

    if not isinstance(data, dict):
        raise ValidationError(message="Request payload failed validation.")

    vote = data.get("vote")
    if not isinstance(vote, str) or vote not in ("approve", "reject"):
        raise ValidationError(
            message="Request payload failed validation.",
            details={"field": "vote", "reason": "must be 'approve' or 'reject'"},
        )

    note_raw = data.get("note", "")
    note = str(note_raw) if note_raw is not None else ""

    # 3. Resolve ApprovalService from application state or construct with state singletons
    approval_service: ApprovalService | None = getattr(request.app.state, "approval_service", None)
    if approval_service is None:
        pool = request.app.state.pool
        bus = request.app.state.bus
        payments = getattr(request.app.state, "payments", None)
        approval_service = ApprovalService(pool=pool, bus=bus, payments=payments)
        request.app.state.approval_service = approval_service

    # 4. Orchestrate vote submission
    outcome = await approval_service.submit_vote(
        hold_id=hold_id,
        voter_sub=principal.sub,
        voter_role=principal.role,
        vote=vote,
        note=note,
    )

    return JSONResponse(outcome.to_dict(), status_code=200)
