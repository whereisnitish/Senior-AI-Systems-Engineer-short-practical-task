"""Account creation, validation, handle suggestions and the 150-character bio limit."""

from __future__ import annotations

import pytest

from app.enums import OperatorRole, ProvisioningStatus, TaskStatus, TaskType
from app.errors import ValidationFailed
from app.models import InstagramAccount
from app.services.handles import brand_key, handle_problems, suggest_handles
from tests.conftest import HANDLE, PROFILE, T0


def test_create_account_creates_identity_tasks_with_owner_and_deadline(env, team, account):
    tasks = env.tasks(account)
    assert sorted(t.task_type.value for t in tasks) == [
        "assign_company_email",
        "assign_company_phone",
        "handle_availability_check",
    ]
    for task in tasks:
        assert task.owner_id == team["owner"]
        assert task.supervisor_id == team["security"]  # owner's supervisor is the escalation target
        assert task.due_at > T0
        assert task.status == TaskStatus.PENDING
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_HANDLE_CHECK
        assert len(acc.steps) == 10
        assert acc.suggested_handles[0] == HANDLE
        assert acc.bio_char_count == len(PROFILE["bio"])


def test_duplicate_brand_returns_existing_record(env, team, account):
    with env.container.uow() as s:
        again, created = env.container.provisioning.create_account(
            s, brand_name="  lumen lab TEST-brand ", owner_id=team["owner"], actor=env.actor(team["owner"])
        )
    assert created is False and again.id == account
    assert len(env.tasks(account)) == 3


def test_handle_suggestions_are_deterministic_and_format_checked():
    first = suggest_handles("Lumen Lab Test Brand", ["shop"])
    assert first == suggest_handles("Lumen Lab Test Brand", ["shop"])
    assert "lumenlabtestbrand_shop" in first
    assert all(not handle_problems(h) and len(h) <= 30 for h in first)
    folded = suggest_handles("Café Ünïcode & Co., Ltd.")
    assert folded and all(not handle_problems(h) for h in folded)
    assert brand_key("Café Ünïcode Ltd") == "cafe-unicode"


@pytest.mark.parametrize(
    "handle,ok",
    [("brand_hq.team", True), ("a" * 30, True), ("a" * 31, False), (".abc", False), ("abc.", False), ("a..b", False), ("Hello!", False), ("1234", False)],
)
def test_handle_format_rules(handle, ok):
    assert (not handle_problems(handle)) is ok


def test_handle_suggestion_api_never_claims_availability(env, team, account):
    client = env.client()
    body = client.get(f"/api/v1/accounts/{account}/handle-suggestions", headers=env.headers(team["owner"], OperatorRole.VIEWER)).json()
    assert body["suggestions"] and all(s["availability"] == "unknown" for s in body["suggestions"])
    assert "availability unknown" in body["note"]


def test_api_create_list_and_get_account(env, team):
    client = env.client()
    headers = env.headers(team["owner"], OperatorRole.OPERATOR)
    payload = {"brand_name": "Lumen Lab Test Brand", "owner_id": team["owner"], "profile": PROFILE, "is_synthetic": True}
    first = client.post("/api/v1/accounts", json=payload, headers=headers)
    assert first.status_code == 201 and first.json()["created"] is True
    second = client.post("/api/v1/accounts", json=payload, headers=headers)
    assert second.status_code == 200 and second.json()["created"] is False
    assert second.json()["account"]["id"] == first.json()["account"]["id"]
    listing = client.get("/api/v1/accounts", headers=headers).json()
    assert len(listing) == 1
    detail = client.get(f"/api/v1/accounts/{listing[0]['id']}", headers=headers).json()
    assert detail["provisioning_status"] == "awaiting_handle_check"
    assert len(detail["open_tasks"]) == 3 and len(detail["steps"]) == 10
    assert detail["handles"]["suggestion_note"].startswith("format-checked only")


def test_account_owner_must_exist_and_be_active(env, team):
    with pytest.raises(ValidationFailed):
        with env.container.uow() as s:
            env.container.provisioning.create_account(s, brand_name="Other Brand", owner_id="per_" + "0" * 32, actor=env.actor(team["owner"]))
    response = env.client().post(
        "/api/v1/accounts", json={"brand_name": "Other", "owner_id": "not-an-id"}, headers=env.headers(team["owner"])
    )
    assert response.status_code == 422


def test_bio_limit_150_characters_enforced_by_api(env, team):
    client = env.client()
    headers = env.headers(team["owner"], OperatorRole.OPERATOR)
    too_long = {**PROFILE, "bio": "x" * 151}
    response = client.post("/api/v1/accounts", json={"brand_name": "Bio Brand", "owner_id": team["owner"], "profile": too_long}, headers=headers)
    assert response.status_code == 422
    assert any("bio" in d["loc"] for d in response.json()["error"]["details"])
    exactly = {**PROFILE, "bio": "y" * 150}
    ok = client.post("/api/v1/accounts", json={"brand_name": "Bio Brand", "owner_id": team["owner"], "profile": exactly}, headers=headers)
    assert ok.status_code == 201
    assert ok.json()["account"]["profile"]["bio_char_count"] == 150


def test_bio_limit_enforced_by_service(env, team, account):
    with pytest.raises(ValidationFailed):
        with env.container.uow() as s:
            env.container.provisioning.set_profile_spec(s, account, {"bio": "z" * 151}, actor=env.actor(team["owner"]))


def test_profile_link_must_be_https(env, team):
    response = env.client().post(
        "/api/v1/accounts",
        json={"brand_name": "Link Brand", "owner_id": team["owner"], "profile": {**PROFILE, "profile_link": "http://insecure.example"}},
        headers=env.headers(team["owner"]),
    )
    assert response.status_code == 422


def test_task_instructions_reference_brand_and_safety_rules(env, team, account):
    handle_task = env.open_task(account, TaskType.HANDLE_AVAILABILITY_CHECK)
    assert "Lumen Lab Test Brand" in handle_task.title
    assert HANDLE in handle_task.description
    assert "SAFETY RULES" in handle_task.description
    assert "NOT proof of availability" in handle_task.description


def test_signup_task_created_only_after_handle_and_contacts(env, team, account):
    actor = env.actor(team["owner"], OperatorRole.ADMIN)
    env.complete_type(account, TaskType.HANDLE_AVAILABILITY_CHECK, actor)
    assert not env.tasks(account, TaskType.ACCOUNT_SIGNUP)
    env.complete_type(account, TaskType.ASSIGN_COMPANY_EMAIL, actor)
    env.complete_type(account, TaskType.ASSIGN_COMPANY_PHONE, actor)
    signup = env.open_task(account, TaskType.ACCOUNT_SIGNUP)
    assert f"@{HANDLE}" in signup.title and "IT-REQ-4821" in signup.description
    assert "i***@testco.example" in signup.description  # masked hint only
    assert "ig-lumenlab@testco.example" not in signup.description
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.AWAITING_SIGNUP
        assert acc.company_phone_hint.endswith("23") and "7700900" not in acc.company_phone_hint


def test_non_company_email_domain_is_rejected(env, team, account):
    with pytest.raises(ValidationFailed):
        env.complete_type(
            account, TaskType.ASSIGN_COMPANY_EMAIL, env.actor(team["owner"], OperatorRole.ADMIN),
            {"email_assignment_ref": "IT-1", "email_address": "someone@gmail.com", "mailbox_control": "company_controlled"},
        )


def test_full_provisioning_reaches_provisioned_with_evidence(env, team, account):
    env.provision(account, team["owner"])
    with env.container.uow() as s:
        acc = s.get(InstagramAccount, account)
        assert acc.provisioning_status == ProvisioningStatus.PROVISIONED
        assert env.container.provisioning.provisioning_gaps(acc) == []
        assert all(step.evidence_ref for step in acc.steps)
        assert acc.backup_codes_verification.value == "integration_verified"  # dev vault metadata confirms presence
        assert acc.two_factor_verification.value == "human_confirmed"  # no integration can read Instagram 2FA
