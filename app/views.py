"""Serialisers shared by the API, dashboard and reports.

Explicit field lists (no ORM auto-dumping) so nothing sensitive can leak by
accident: only references, masked hints and metadata are ever exposed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.enums import FindingStatus, OffboardingActionStatus, TaskStatus
from app.models import (
    AuditFinding,
    HumanTask,
    InstagramAccount,
    Notification,
    OffboardingAction,
    OffboardingCase,
    Person,
    ProxyEndpoint,
    ProxyEvent,
    ProxySession,
)
from app.security.secret_handling import mask_email
from app.services.task_manager import ACTIVE_STATUSES
from app.services.task_types import get_spec


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def person_ref(person: Person | None) -> dict[str, Any] | None:
    if person is None:
        return None
    return {"id": person.id, "name": person.full_name, "status": person.status.value}


def person_view(person: Person) -> dict[str, Any]:
    return {
        "id": person.id,
        "full_name": person.full_name,
        "email_masked": mask_email(person.email),
        "status": person.status.value,
        "supervisor_id": person.supervisor_id,
        "responsibilities": list(person.responsibilities or []),
        "is_synthetic": person.is_synthetic,
        "last_access_review_at": iso(person.last_access_review_at),
    }


def task_view(task: HumanTask, now: datetime, *, detail: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": task.id,
        "task_type": task.task_type.value,
        "origin": task.origin.value,
        "account_id": task.account_id,
        "title": task.title,
        "owner": person_ref(task.owner),
        "supervisor": person_ref(task.supervisor),
        "status": task.status.value,
        "priority": task.priority.value,
        "due_at": iso(task.due_at),
        "is_overdue": task.status in ACTIVE_STATUSES and now > task.due_at,
        "created_at": iso(task.created_at),
        "updated_at": iso(task.updated_at),
        "attempt_count": task.attempt_count,
        "reminder_count": task.reminder_count,
        "last_reminder_at": iso(task.last_reminder_at),
        "escalation_count": task.escalation_count,
        "escalated_at": iso(task.escalated_at),
        "completed_at": iso(task.completed_at),
        "completed_by_id": task.completed_by_id,
        "completion_evidence_ref": task.completion_evidence_ref,
        "verification_source": task.verification_source.value,
        "blocker_detail": task.blocker_detail,
        "error_detail": task.error_detail,
        "idempotency_key": task.idempotency_key,
    }
    if detail:
        spec = get_spec(task.task_type)
        out["description"] = task.description
        out["outcome"] = task.outcome or {}
        out["completion_note"] = task.completion_note
        out["completion_requirements"] = {
            "evidence_ref": spec.evidence_hint,
            "outcome_fields": [
                {"name": f.name, "kind": f.kind, "label": f.label, "required": f.required, "choices": list(f.choices)}
                for f in spec.outcome_fields
            ],
        }
        out["events"] = [
            {
                "event_type": e.event_type,
                "from_status": e.from_status,
                "to_status": e.to_status,
                "actor_id": e.actor_id,
                "detail": e.detail,
                "at": iso(e.created_at),
            }
            for e in task.events
        ]
    return out


def account_view(session: Session, account: InstagramAccount, now: datetime, gaps: list[str]) -> dict[str, Any]:
    open_tasks = session.scalars(
        select(HumanTask)
        .where(HumanTask.account_id == account.id, HumanTask.status.in_(list(ACTIVE_STATUSES)))
        .order_by(HumanTask.due_at)
    ).all()
    open_findings = session.scalars(
        select(AuditFinding).where(AuditFinding.account_id == account.id, AuditFinding.status == FindingStatus.OPEN)
    ).all()
    return {
        "id": account.id,
        "brand_name": account.brand_name,
        "is_synthetic": account.is_synthetic,
        "environment": account.environment,
        "provisioning_status": account.provisioning_status.value,
        "provisioned_at": iso(account.provisioned_at),
        "owner": person_ref(account.owner),
        "handles": {
            "suggested": list(account.suggested_handles or []),
            "suggestion_note": "format-checked only; availability is checked by a human in the official Instagram interface",
            "selected": account.selected_handle,
            "status": account.handle_status.value,
        },
        "company_contacts": {
            "email_assignment_ref": account.company_email_ref,
            "email_hint": account.company_email_hint,
            "email_domain": account.company_email_domain,
            "email_control": account.company_email_control.value,
            "phone_assignment_ref": account.company_phone_ref,
            "phone_hint": account.company_phone_hint,
            "phone_control": account.company_phone_control.value,
        },
        "recovery": {
            "email_control": account.recovery_email_control.value,
            "email_verification": account.recovery_email_verification.value,
            "phone_control": account.recovery_phone_control.value,
            "phone_verification": account.recovery_phone_verification.value,
            "last_verified_at": iso(account.recovery_last_verified_at),
        },
        "two_factor": {
            "status": account.two_factor_status.value,
            "method": account.two_factor_method.value,
            "verification": account.two_factor_verification.value,
        },
        "backup_codes": {
            "vault_ref": account.backup_codes_vault_ref,
            "status": account.backup_codes_status.value,
            "verification": account.backup_codes_verification.value,
        },
        "vault_refs": {
            "password_vault_ref": account.password_vault_ref,
            "password_ref_verification": account.password_ref_verification.value,
            "other": dict(account.other_vault_refs or {}),
        },
        "profile": {
            "profile_name": account.profile_name,
            "bio": account.bio,
            "bio_char_count": account.bio_char_count,
            "bio_max_chars": 150,
            "profile_link": account.profile_link,
            "category": account.category,
            "profile_image_ref": account.profile_image_ref,
        },
        "business_account_status": account.business_account_status.value,
        "meta": {
            "link_status": account.meta_link_status.value,
            "business_ref": account.meta_business_ref,
            "verification": account.meta_link_verification.value,
        },
        "steps": [
            {
                "step": s.step.value,
                "state": s.state.value,
                "verification": s.verification.value,
                "evidence_ref": s.evidence_ref,
                "task_id": s.task_id,
                "completed_at": iso(s.completed_at),
            }
            for s in account.steps
        ],
        "people_and_roles": [
            {
                "assignment_id": a.id,
                "person": person_ref(a.person),
                "platform": a.platform.value,
                "role": a.role.value,
                "role_description": a.role_description,
                "approved": a.approved,
                "status": a.status.value,
                "temporary_test_role": a.is_temporary_test_role,
                "verification": a.verification.value,
                "evidence_ref": a.evidence_ref,
                "last_verified_at": iso(a.last_verified_at),
            }
            for a in account.assignments
        ],
        "blocker": (
            {
                "code": account.blocker_code,
                "detail": account.blocker_detail,
                "task_id": account.blocker_task_id,
                "since": iso(account.blocked_at),
                "status_before_block": account.status_before_block.value if account.status_before_block else None,
            }
            if account.blocker_code
            else None
        ),
        "provisioning_gaps": gaps,
        "open_tasks": [task_view(t, now) for t in open_tasks],
        "open_findings": [finding_view(f) for f in open_findings],
        "last_verified_at": iso(account.last_verified_at),
        "verification_source": account.verification_source.value,
        "evidence_ref": account.evidence_ref,
        "created_at": iso(account.created_at),
        "updated_at": iso(account.updated_at),
    }


def finding_view(finding: AuditFinding) -> dict[str, Any]:
    task = finding.remediation_task
    return {
        "id": finding.id,
        "account_id": finding.account_id,
        "check_name": finding.check_name,
        "fingerprint": finding.fingerprint,
        "severity": finding.severity.value,
        "description": finding.description,
        "verification": finding.verification.value,
        "evidence_ref": finding.evidence_ref,
        "status": finding.status.value,
        "first_detected_at": iso(finding.first_detected_at),
        "last_detected_at": iso(finding.last_detected_at),
        "occurrence_count": finding.occurrence_count,
        "resolved_at": iso(finding.resolved_at),
        "resolution_note": finding.resolution_note,
        "remediation_task": (
            {
                "id": task.id,
                "title": task.title,
                "status": task.status.value,
                "owner": person_ref(task.owner),
                "due_at": iso(task.due_at),
                "origin": task.origin.value,
            }
            if task
            else None
        ),
        "remediation_blocker": finding.remediation_blocker,
    }


def action_view(action: OffboardingAction) -> dict[str, Any]:
    task = action.task
    return {
        "id": action.id,
        "action_type": action.action_type.value,
        "account_id": action.account_id,
        "target_ref": action.target_ref,
        "description": action.description,
        "owner": person_ref(action.owner),
        "status": action.status.value,
        "verification": action.verification.value,
        "evidence_ref": action.evidence_ref,
        "blocker_code": action.blocker_code,
        "blocker_detail": action.blocker_detail,
        "task": {"id": task.id, "status": task.status.value, "due_at": iso(task.due_at)} if task else None,
        "detail": action.detail or {},
        "completed_at": iso(action.completed_at),
    }


def case_view(case: OffboardingCase) -> dict[str, Any]:
    actions = [action_view(a) for a in case.actions]
    return {
        "id": case.id,
        "person": person_ref(case.person),
        "status": case.status.value,
        "reason": case.reason,
        "replacement_admin": person_ref(case.replacement_admin),
        "created_at": iso(case.created_at),
        "closed_at": iso(case.closed_at),
        "reconcile_count": case.reconcile_count,
        "completed": [a for a in actions if a["status"] == OffboardingActionStatus.COMPLETED.value],
        "pending": [a for a in actions if a["status"] in (OffboardingActionStatus.PENDING.value, OffboardingActionStatus.IN_PROGRESS.value)],
        "blocked": [a for a in actions if a["status"] == OffboardingActionStatus.BLOCKED.value],
        "cancelled": [a for a in actions if a["status"] == OffboardingActionStatus.CANCELLED.value],
    }


def notification_view(n: Notification) -> dict[str, Any]:
    return {
        "id": n.id,
        "task_id": n.task_id,
        "recipient": person_ref(n.recipient),
        "kind": n.kind.value,
        "channel": n.channel,
        "subject": n.subject,
        "delivery_status": n.delivery_status.value,
        "delivered": n.delivery_status.value == "sent",
        "attempt_count": n.attempt_count,
        "last_error": n.last_error,
        "created_at": iso(n.created_at),
        "sent_at": iso(n.sent_at),
    }


def proxy_view(p: ProxyEndpoint) -> dict[str, Any]:
    return {
        "id": p.id,
        "endpoint": f"{p.scheme}://{p.host}:{p.port}",
        "credential_ref": p.credential_ref,
        "approved": p.approved,
        "priority": p.priority,
        "health_status": p.health_status.value,
        "consecutive_failures": p.consecutive_failures,
        "total_failures": p.total_failures,
        "total_checks": p.total_checks,
        "last_check_at": iso(p.last_check_at),
        "last_success_at": iso(p.last_success_at),
        "last_failure_at": iso(p.last_failure_at),
        "last_failure_kind": p.last_failure_kind,
        "last_latency_ms": round(p.last_latency_ms, 1) if p.last_latency_ms is not None else None,
        "cooldown_until": iso(p.cooldown_until),
    }


def proxy_session_view(s: ProxySession) -> dict[str, Any]:
    return {
        "id": s.id,
        "account_id": s.account_id,
        "purpose": s.purpose,
        "proxy_id": s.proxy_id,
        "status": s.status.value,
        "started_at": iso(s.started_at),
        "last_used_at": iso(s.last_used_at),
        "failover_count": s.failover_count,
        "rate_limited_until": iso(s.rate_limited_until),
        "pause_reason": s.pause_reason,
        "review_task_id": s.review_task_id,
        "ended_at": iso(s.ended_at),
        "end_reason": s.end_reason,
    }


def proxy_event_view(e: ProxyEvent) -> dict[str, Any]:
    return {
        "id": e.id,
        "proxy_id": e.proxy_id,
        "session_id": e.session_id,
        "event_type": e.event_type,
        "outcome": e.outcome,
        "detail": e.detail,
        "at": iso(e.created_at),
    }


def is_active(status: TaskStatus) -> bool:
    return status in ACTIVE_STATUSES
