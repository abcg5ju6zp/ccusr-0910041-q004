"""可版本化策略选择/执行机制的回归测试。

覆盖：
- 一次请求在请求、异常、响应、结束阶段始终使用同一版本
- 规则优先级、显式豁免、稳定分桶灰度、比例调整与立即回退
- 灰度/回退不影响在途请求
- 审计记录包含选择原因，但不泄露凭据
- 既有蓝图/应用级中间件顺序保持不变
"""

from __future__ import annotations

import pytest

from sanic import (
    PolicyRegistry,
    PolicyVersion,
    Rollout,
    Sanic,
    SelectionReason,
)
from sanic.exceptions import SanicException
from sanic.policies.core import (
    POLICY_VERSION_HEADER,
    redact_headers,
    stable_bucket,
)
from sanic.response import json, text


TENANT_HEADER = "x-tenant-id"
IDENTITY_HEADER = "x-rollout-key"
SECRET = "super-secret-token"


@pytest.fixture
def registry() -> PolicyRegistry:
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
        ),
        tenants={"acme"},
    )
    return registry


@pytest.fixture
def wired_app(app: Sanic, registry: PolicyRegistry):
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return json({"ok": True})

    return app, registry


# --------------------------------------------------------------------- #
# 基础选择
# --------------------------------------------------------------------- #


def test_default_version_without_tenant(wired_app):
    app, registry = wired_app
    _, response = app.test_client.get("/ok")
    assert response.status == 200
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_tenant_canary_included(wired_app):
    app, _ = wired_app
    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-1"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"


def test_stable_bucket_is_deterministic():
    first = stable_bucket("security", "user-1")
    second = stable_bucket("security", "user-1")
    other_registry = stable_bucket("other", "user-1")
    assert first == second
    assert 0 <= first < 10_000
    assert other_registry != first


def test_zero_percentage_falls_to_default(wired_app):
    app, registry = wired_app
    registry.canary("v2", 0.0)
    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-1"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_percentage_change_only_affects_new_requests(wired_app):
    app, registry = wired_app

    _, before = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-1"}
    )
    assert before.headers[POLICY_VERSION_HEADER] == "security=v2"

    registry.canary("v2", 0.0)

    _, after = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-1"}
    )
    assert after.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_same_identity_stable_across_requests(wired_app):
    app, registry = wired_app
    # 找到一个恰好在 ~50% 边界附近仍稳定的身份：固定桶位意味着
    # 同一身份在相同比例下永远得到同一结果
    registry.canary("v2", 100.0)
    results = {
        app.test_client.get(
            "/ok",
            headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-42"},
        )[1].headers[POLICY_VERSION_HEADER]
        for _ in range(5)
    }
    assert results == {"security=v2"}


def test_rollback_immediately_restores_default(wired_app):
    app, registry = wired_app
    registry.rollback("v1")
    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "user-1"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


# --------------------------------------------------------------------- #
# 优先级与豁免
# --------------------------------------------------------------------- #


def test_rule_priority(app: Sanic):
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(name="v2", priority=1, rollout=Rollout(100.0)),
        tenants={"acme"},
    )
    registry.add(
        PolicyVersion(name="v3", priority=10, rollout=Rollout(100.0)),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v3"


def test_exempt_tenant_rule_wins_over_canary(app: Sanic):
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(name="v2", rollout=Rollout(100.0)), tenants={"acme"}
    )
    registry.exempt("v1", tenants=["acme"])
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"
    direct = registry.select(tenant="acme", identity="u")
    assert direct.reason is SelectionReason.EXEMPT


def test_exempt_path_resolver(app: Sanic):
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(name="v2", rollout=Rollout(100.0)), tenants={"acme"}
    )
    manager = app.policy_manager
    manager.add(registry)
    manager.exempt_paths(r"^/healthz")

    @app.get("/healthz")
    async def healthz(request):
        return text("ok")

    seen = []
    manager.audit_sink = lambda request, event: seen.append(event)

    _, response = app.test_client.get(
        "/healthz", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"
    selected = [e for e in seen if e["stage"] == "selected"]
    assert selected[0]["reason"] == "exempt"


def test_pinned_version(app: Sanic):
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(PolicyVersion(name="v2"))
    app.policy_manager.add(registry)
    app.policy_manager.pinned_resolver = lambda request: request.headers.get(
        "x-debug-pin"
    )

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok", headers={"x-debug-pin": "v2"})
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"
    direct = registry.select(pinned_version="v2")
    assert direct.reason is SelectionReason.PINNED


# --------------------------------------------------------------------- #
# 同一版本贯穿请求 → 异常 → 响应 → 结束
# --------------------------------------------------------------------- #


def test_single_version_used_throughout_lifecycle(app: Sanic):
    registry = PolicyRegistry("security")
    seen = {"request": [], "response": [], "complete": []}

    v1 = PolicyVersion(
        name="v1",
        on_request=lambda request: seen["request"].append("v1"),
        on_response=lambda request, response: seen["response"].append("v1"),
        on_complete=lambda request, exception=None: seen["complete"].append(
            ("v1", exception)
        ),
    )
    v2 = PolicyVersion(
        name="v2",
        rollout=Rollout(100.0),
        on_request=lambda request: seen["request"].append("v2"),
        on_response=lambda request, response: seen["response"].append("v2"),
        on_complete=lambda request, exception=None: seen["complete"].append(
            ("v2", exception)
        ),
    )
    registry.add(v1, make_default=True)
    registry.add(v2, tenants={"acme"})
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert seen["request"] == ["v2"]
    assert seen["response"] == ["v2"]
    assert seen["complete"] == [("v2", None)]


def test_exception_phase_uses_same_version(app: Sanic):
    registry = PolicyRegistry("security")
    captured = []

    async def v2_on_exception(request, exception):
        captured.append(("v2", type(exception).__name__))

    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
            on_exception=v2_on_exception,
        ),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)

    @app.get("/boom")
    async def handler(request):
        raise SanicException("nope", status_code=400)

    _, response = app.test_client.get(
        "/boom", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.status == 400
    assert captured == [("v2", "SanicException")]
    # 响应阶段仍能确认使用的是 v2
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"


def test_exception_hook_can_return_response(app: Sanic):
    registry = PolicyRegistry("security")

    async def recover(request, exception):
        return json({"recovered": True}, status=200)

    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
            on_exception=recover,
        ),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)

    @app.get("/boom")
    async def handler(request):
        raise SanicException("nope", status_code=400)

    _, response = app.test_client.get(
        "/boom", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.status == 200
    assert response.json == {"recovered": True}
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"


def test_exception_hook_failure_does_not_break_error_handling(app: Sanic):
    registry = PolicyRegistry("security")

    async def broken(request, exception):
        raise RuntimeError("hook exploded")

    registry.add(
        PolicyVersion(
            name="v1", on_exception=broken
        ),
        make_default=True,
    )
    app.policy_manager.add(registry)

    @app.get("/boom")
    async def handler(request):
        raise SanicException("nope", status_code=400)

    _, response = app.test_client.get("/boom")
    assert response.status == 400
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_inflight_request_keeps_version_after_rollback(app: Sanic):
    """请求进入后执行回退，在途请求的响应/结束阶段仍使用旧版本。"""

    registry = PolicyRegistry("security")
    stages = {}

    def v2_request(request):
        # 在请求中途立即回退并调整灰度
        registry.rollback("v1")

    def v2_response(request, response):
        stages["response_version"] = response.headers.get(
            POLICY_VERSION_HEADER
        )

    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
            on_request=v2_request,
            on_response=v2_response,
        ),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    # 在途请求自始至终是 v2
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"
    # 回退后的下一个新请求落到 v1
    _, second = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u-2"}
    )
    assert second.headers[POLICY_VERSION_HEADER] == "security=v1"


# --------------------------------------------------------------------- #
# 中间件顺序
# --------------------------------------------------------------------- #


def test_policy_runs_after_existing_middleware_chain(app: Sanic):
    order = []

    @app.on_request
    def app_middleware(request):
        order.append("app_request")

    @app.on_response
    def app_response_middleware(request, response):
        order.append("app_response")

    registry = PolicyRegistry("security")
    registry.add(
        PolicyVersion(
            name="v1",
            on_request=lambda request: order.append("policy_request"),
            on_response=lambda request, response: order.append(
                "policy_response"
            ),
        ),
        make_default=True,
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        order.append("handler")
        return text("ok")

    app.test_client.get("/ok")
    assert order == [
        "app_request",
        "policy_request",
        "handler",
        "app_response",
        "policy_response",
    ]


def test_blueprint_middleware_order_preserved(app: Sanic):
    from sanic import Blueprint

    order = []
    bp = Blueprint("bp")

    @bp.on_request
    def bp_request(request):
        order.append("bp_request")

    @bp.on_response
    def bp_response(request, response):
        order.append("bp_response")

    @bp.get("/ok")
    async def handler(request):
        order.append("handler")
        return text("ok")

    app.blueprint(bp)

    registry = PolicyRegistry("security")
    registry.add(
        PolicyVersion(
            name="v1",
            on_request=lambda request: order.append("policy_request"),
            on_response=lambda request, response: order.append(
                "policy_response"
            ),
        ),
        make_default=True,
    )
    app.policy_manager.add(registry)

    app.test_client.get("/ok")
    assert order == [
        "bp_request",
        "policy_request",
        "handler",
        "bp_response",
        "policy_response",
    ]


def test_policy_request_hook_can_short_circuit(app: Sanic):
    registry = PolicyRegistry("security")
    handler_called = False
    registry.add(
        PolicyVersion(
            name="v1",
            on_request=lambda request: text("blocked", status=403),
        ),
        make_default=True,
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        nonlocal handler_called
        handler_called = True
        return text("ok")

    _, response = app.test_client.get("/ok")
    assert response.status == 403
    assert response.text == "blocked"
    assert handler_called is False


# --------------------------------------------------------------------- #
# 审计
# --------------------------------------------------------------------- #


def test_audit_records_reason_without_credentials(app: Sanic):
    events = []
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
            metadata={"rule_owner": "security-team", "revision": 7},
        ),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)
    app.policy_manager.audit_sink = lambda request, event: events.append(event)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get(
        "/ok",
        headers={
            TENANT_HEADER: "acme",
            IDENTITY_HEADER: "user-1",
            "authorization": f"Bearer {SECRET}",
            "cookie": f"session={SECRET}",
            "x-api-key": SECRET,
        },
    )
    assert response.status == 200

    selected = [e for e in events if e["stage"] == "selected"][0]
    completed = [e for e in events if e["stage"] == "completed"][0]

    assert selected["version"] == "v2"
    assert selected["reason"] == "canary_included"
    assert selected["tenant"] == "acme"
    assert isinstance(selected["bucket"], int)
    assert selected["metadata"] == {
        "rule_owner": "security-team",
        "revision": 7,
    }
    assert completed["reason"] == "canary_included"
    assert "duration_ms" in completed

    blob = repr(events)
    assert SECRET not in blob
    assert "authorization" not in blob.lower()
    assert "cookie" not in blob.lower()


def test_redact_headers_helper():
    safe = redact_headers(
        {
            "Authorization": "Bearer x",
            "Cookie": "a=b",
            "X-Api-Key": "k",
            "X-Tenant-Id": "acme",
            "Accept": "application/json",
        }
    )
    assert "Authorization" not in safe
    assert "Cookie" not in safe
    assert "X-Api-Key" not in safe
    assert safe["X-Tenant-Id"] == "acme"
    assert safe["Accept"] == "application/json"


def test_unconfigured_registry_is_noop(app: Sanic):
    events = []
    registry = PolicyRegistry("empty")
    app.policy_manager.add(registry)
    app.policy_manager.audit_sink = lambda request, event: events.append(event)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok")
    assert response.status == 200
    assert POLICY_VERSION_HEADER not in response.headers
    selected = [e for e in events if e["stage"] == "selected"][0]
    assert selected["version"] is None
    assert selected["reason"] == "unconfigured"


# --------------------------------------------------------------------- #
# Rollout 单元行为
# --------------------------------------------------------------------- #


def test_rollout_cutoff_and_bounds():
    rollout = Rollout(25.0)
    assert rollout.cutoff == 2500
    assert rollout.includes(0)
    assert rollout.includes(2499)
    assert not rollout.includes(2500)
    with pytest.raises(ValueError):
        Rollout(120.0)
    rollout.percentage = 0.0
    assert rollout.cutoff == 0
    assert not rollout.includes(0)


def test_duplicate_version_rejected(registry: PolicyRegistry):
    with pytest.raises(ValueError):
        registry.add(PolicyVersion(name="v1"))


def test_unknown_version_operations_rejected(registry: PolicyRegistry):
    with pytest.raises(ValueError):
        registry.canary("v9", 10.0)
    with pytest.raises(ValueError):
        registry.rollback("v9")


def test_zero_percentage_without_identity_uses_default(app: Sanic):
    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(name="v2", rollout=Rollout(0.0)),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)
    app.policy_manager.identity_resolver = lambda request: None

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok", headers={TENANT_HEADER: "acme"})
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_tenant_is_stable_bucket_key_without_identity(app: Sanic):
    """没有细粒度身份时按租户整桶灰度，多次请求结果一致。"""

    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(name="v2", rollout=Rollout(100.0)),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)
    app.policy_manager.identity_resolver = lambda request: None

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    versions = {
        app.test_client.get("/ok", headers={TENANT_HEADER: "acme"})[
            1
        ].headers[POLICY_VERSION_HEADER]
        for _ in range(3)
    }
    assert versions == {"security=v2"}


def test_response_hook_replacement_gets_version_header(app: Sanic):
    """on_response 返回新响应时，版本确认头必须写在最终响应上。"""

    registry = PolicyRegistry("security")

    def replace_response(request, response):
        return text("replaced", status=202)

    registry.add(
        PolicyVersion(name="v1", on_response=replace_response),
        make_default=True,
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok")
    assert response.status == 202
    assert response.text == "replaced"
    assert response.headers[POLICY_VERSION_HEADER] == "security=v1"


def test_multiple_registries_announced_together(app: Sanic):
    security = PolicyRegistry("security")
    limits = PolicyRegistry("limits")
    security.add(PolicyVersion(name="s1"), make_default=True)
    limits.add(PolicyVersion(name="l1"), make_default=True)
    app.policy_manager.add(security)
    app.policy_manager.add(limits)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok")
    announced = response.headers[POLICY_VERSION_HEADER]
    # 按注册顺序宣告两个注册表各自的版本
    assert announced == "security=s1,limits=l1"


def test_async_audit_sink_is_awaited(app: Sanic):
    import asyncio

    completed = []

    async def sink(request, event):
        await asyncio.sleep(0)
        completed.append(event)

    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    app.policy_manager.add(registry)
    app.policy_manager.audit_sink = sink

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    app.test_client.get("/ok")
    stages = {e["stage"] for e in completed}
    assert stages == {"selected", "completed"}


def test_failed_audit_sink_does_not_break_request(app: Sanic):
    def boom(request, event):
        raise RuntimeError("audit backend down")

    registry = PolicyRegistry("security")
    registry.add(PolicyVersion(name="v1"), make_default=True)
    app.policy_manager.add(registry)
    app.policy_manager.audit_sink = boom

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get("/ok")
    assert response.status == 200


def test_request_hook_exception_handled_by_same_version(app: Sanic):
    """on_request 自身抛出的异常，由同一版本的 on_exception 观测。"""

    registry = PolicyRegistry("security")
    captured = []

    def boom(request):
        raise SanicException("policy rejected", status_code=403)

    async def observe(request, exception):
        selection = app.policy_manager.selection_for(request, "security")
        captured.append((selection.version_name, type(exception).__name__))

    registry.add(PolicyVersion(name="v1"), make_default=True)
    registry.add(
        PolicyVersion(
            name="v2",
            rollout=Rollout(100.0),
            on_request=boom,
            on_exception=observe,
        ),
        tenants={"acme"},
    )
    app.policy_manager.add(registry)

    @app.get("/ok")
    async def handler(request):
        return text("ok")

    _, response = app.test_client.get(
        "/ok", headers={TENANT_HEADER: "acme", IDENTITY_HEADER: "u"}
    )
    assert response.status == 403
    assert captured == [("v2", "SanicException")]
    assert response.headers[POLICY_VERSION_HEADER] == "security=v2"
