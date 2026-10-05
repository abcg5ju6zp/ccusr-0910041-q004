import json
import logging

import pytest

from sanic import Sanic, text
from sanic.response import json as sjson
from sanic.strategies import (
    PolicyError,
    SelectionReason,
    stable_bucket,
)


VERSION_HEADER = "X-Policy-Version"


def make_app_with_versions(
    name: str = "policy",
    *,
    v2_rollout: float = 100.0,
    v2_tenants=None,
    allow_override: bool = False,
):
    app = Sanic(name)
    strategy = app.add_policy_strategy(
        "ratelimit", allow_override=allow_override
    )
    strategy.add_version(
        "v1", payload={"limit": 100}, fallback=True, priority=0
    )
    strategy.add_version(
        "v2",
        payload={"limit": 10},
        priority=10,
        rollout=v2_rollout,
        tenants=v2_tenants,
    )
    return app, strategy


# ------------------------------------------------------------ #
# 基本选择、冻结与响应确认
# ------------------------------------------------------------ #


def test_selects_version_by_rollout_and_marks_response(app: Sanic):
    app, strategy = make_app_with_versions("full")

    @app.route("/")
    async def handler(request):
        decision = app.policy_decision(request, "ratelimit")
        return text(f"{decision.version_name}:{decision.payload['limit']}")

    _, response = app.test_client.get("/", headers={"x-tenant-id": "acme"})

    assert response.status == 200
    assert response.text == "v2:10"
    assert response.headers[VERSION_HEADER] == "ratelimit=v2"


def test_decision_is_frozen_for_whole_request(app: Sanic):
    app, strategy = make_app_with_versions("frozen")
    order = []

    @app.on_request
    async def user_request_middleware(request):
        order.append(
            (
                "user-request",
                app.policy_decision(request, "ratelimit").version_name,
            )
        )

    @strategy.on_request("v2")
    async def v2_request_hook(request):
        order.append(
            (
                "policy-request",
                app.policy_decision(request, "ratelimit").version_name,
            )
        )

    @strategy.on_response("v2")
    async def v2_response_hook(request, response):
        order.append(
            (
                "policy-response",
                app.policy_decision(request, "ratelimit").version_name,
            )
        )

    @app.on_response
    async def user_response_middleware(request, response):
        order.append(
            (
                "user-response",
                app.policy_decision(request, "ratelimit").version_name,
            )
        )

    @app.route("/")
    async def handler(request):
        order.append(
            ("handler", app.policy_decision(request, "ratelimit").version_name)
        )
        return text("ok")

    _, response = app.test_client.get("/", headers={"x-tenant-id": "acme"})

    assert response.status == 200
    # 版本钩子位于洋葱模型最内层，不改变现有中间件的相对顺序：
    # 请求阶段用户中间件 -> 版本钩子 -> 处理器；
    # 响应阶段版本钩子 -> 用户响应中间件。
    assert order == [
        ("user-request", "v2"),
        ("policy-request", "v2"),
        ("handler", "v2"),
        ("policy-response", "v2"),
        ("user-response", "v2"),
    ]


def test_same_version_used_in_exception_handling(app: Sanic):
    app, strategy = make_app_with_versions("errors")
    seen = {}

    @strategy.on_response("v2")
    async def v2_response_hook(request, response):
        seen["hook"] = app.policy_decision(request, "ratelimit").version_name
        response.headers["x-hook"] = "v2"

    @app.route("/boom")
    async def boom(request):
        raise RuntimeError("boom")

    _, response = app.test_client.get("/boom", headers={"x-tenant-id": "acme"})

    assert response.status == 500
    # 异常响应同样使用进入时冻结的版本
    assert response.headers[VERSION_HEADER] == "ratelimit=v2"
    assert response.headers["x-hook"] == "v2"
    assert seen["hook"] == "v2"


# ------------------------------------------------------------ #
# 灰度比例与稳定分桶
# ------------------------------------------------------------ #


def test_stable_bucket_is_stable_and_bounded():
    assert stable_bucket("s", "tenant-a") == stable_bucket("s", "tenant-a")
    assert stable_bucket("s", "tenant-a") != stable_bucket("s", "tenant-b")
    for i in range(100):
        assert 0 <= stable_bucket("s", f"t{i}") < 10_000


def test_rollout_zero_uses_fallback(app: Sanic):
    app, strategy = make_app_with_versions("zero", v2_rollout=0)

    @app.route("/")
    async def handler(request):
        return text(
            app.policy_decision(request, "ratelimit").version_name or ""
        )

    _, response = app.test_client.get("/", headers={"x-tenant-id": "acme"})
    assert response.text == "v1"
    assert response.headers[VERSION_HEADER] == "ratelimit=v1"


def test_rollout_partition_is_stable(app: Sanic):
    app = Sanic("partition")
    strategy = app.add_policy_strategy("ratelimit")
    strategy.add_version("v1", fallback=True)
    strategy.add_version("v2", priority=10, rollout=25)

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "ratelimit").version_name)

    tenants = [f"tenant-{i}" for i in range(200)]
    first = {}
    for tenant in tenants:
        _, response = app.test_client.get("/", headers={"x-tenant-id": tenant})
        first[tenant] = response.text

    # 同一租户重复请求结果一致
    for tenant in tenants[:20]:
        _, response = app.test_client.get("/", headers={"x-tenant-id": tenant})
        assert response.text == first[tenant]

    # 大约 25%（允许统计波动）
    v2_share = sum(v == "v2" for v in first.values()) / len(first)
    assert 0.15 < v2_share < 0.35

    # 扩量是单调的：调大灰度比例后，原先命中 v2 的租户仍然命中
    strategy.set_rollout("v2", 50)
    for tenant, chosen in first.items():
        _, response = app.test_client.get("/", headers={"x-tenant-id": tenant})
        if chosen == "v2":
            assert response.text == "v2"


def test_priority_orders_versions(app: Sanic):
    app = Sanic("priority")
    strategy = app.add_policy_strategy("s")
    strategy.add_version("v1", fallback=True)
    strategy.add_version("v2", priority=5, rollout=100)
    strategy.add_version("v3", priority=10, rollout=100)

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "s").version_name)

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.text == "v3"


def test_pinned_tenant_beats_rollout(app: Sanic):
    app = Sanic("pinned")
    strategy = app.add_policy_strategy("s")
    strategy.add_version("v1", fallback=True)
    strategy.add_version(
        "v2", priority=10, rollout=0, tenants=frozenset({"vip"})
    )

    @app.route("/")
    async def handler(request):
        decision = app.policy_decision(request, "s")
        return text(f"{decision.version_name}:{decision.reason.value}")

    _, vip = app.test_client.get("/", headers={"x-tenant-id": "vip"})
    _, regular = app.test_client.get("/", headers={"x-tenant-id": "regular"})

    assert vip.text == "v2:pinned"
    assert regular.text == "v1:fallback"


# ------------------------------------------------------------ #
# 显式豁免
# ------------------------------------------------------------ #


def test_exempt_tenant(app: Sanic):
    app, strategy = make_app_with_versions("exempt")
    strategy.exempt_tenant("special")

    @app.route("/")
    async def handler(request):
        decision = app.policy_decision(request, "ratelimit")
        return text(f"{decision.version_name}:{decision.reason.value}")

    _, response = app.test_client.get("/", headers={"x-tenant-id": "special"})
    assert response.text == "v1:exempt"
    _, other = app.test_client.get("/", headers={"x-tenant-id": "other"})
    assert other.text.startswith("v2:")


def test_exempt_version_is_preferred_when_exempted(app: Sanic):
    app = Sanic("explicit-exempt")
    strategy = app.add_policy_strategy("s")
    strategy.add_version("legacy", fallback=True)
    strategy.add_version("safe", exempt=True)
    strategy.add_version("next", priority=10, rollout=100)
    strategy.exempt_tenant("vip")

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "s").version_name)

    _, response = app.test_client.get("/", headers={"x-tenant-id": "vip"})
    assert response.text == "safe"


def test_exemption_predicate(app: Sanic):
    app, strategy = make_app_with_versions("predicate")

    strategy.add_exemption(
        lambda request, tenant: request.headers.getone("x-bypass", "") == "1"
    )

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "ratelimit").reason.value)

    _, bypassed = app.test_client.get(
        "/", headers={"x-tenant-id": "t", "x-bypass": "1"}
    )
    _, normal = app.test_client.get(
        "/", headers={"x-tenant-id": "t", "x-bypass": "0"}
    )
    assert bypassed.text == SelectionReason.EXEMPT.value
    assert normal.text == SelectionReason.ROLLOUT.value


# ------------------------------------------------------------ #
# 立即回退
# ------------------------------------------------------------ #


def test_immediate_version_rollback(app: Sanic):
    app, strategy = make_app_with_versions("rollback")

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "ratelimit").version_name)

    _, before = app.test_client.get("/", headers={"x-tenant-id": "acme"})
    assert before.text == "v2"

    app.rollback_policy("v2", strategy="ratelimit")

    _, after = app.test_client.get("/", headers={"x-tenant-id": "acme"})
    assert after.text == "v1"
    assert after.headers[VERSION_HEADER] == "ratelimit=v1"

    strategy.restore("v2")
    _, restored = app.test_client.get("/", headers={"x-tenant-id": "acme"})
    assert restored.text == "v2"


def test_rollback_whole_strategy(app: Sanic):
    app, strategy = make_app_with_versions("rollback-all")

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request, "ratelimit").version_name)

    strategy.rollback()

    _, response = app.test_client.get("/", headers={"x-tenant-id": "acme"})
    assert response.text == "v1"


# ------------------------------------------------------------ #
# 覆盖请求头
# ------------------------------------------------------------ #


def test_override_header_respected_only_when_allowed(app: Sanic):
    app, strategy = make_app_with_versions(
        "override", v2_rollout=0, allow_override=True
    )

    @app.route("/")
    async def handler(request):
        return text(
            f"{app.policy_decision(request, 'ratelimit').version_name}:"
            f"{app.policy_decision(request, 'ratelimit').reason.value}"
        )

    _, allowed = app.test_client.get(
        "/", headers={"x-tenant-id": "t", "x-policy-version": "v2"}
    )
    assert allowed.text == "v2:override"

    # 未知版本头被忽略
    _, unknown = app.test_client.get(
        "/", headers={"x-tenant-id": "t", "x-policy-version": "v99"}
    )
    assert unknown.text == "v1:fallback"

    # 默认不允许覆盖
    app2, _ = make_app_with_versions("override-off", v2_rollout=0)

    @app2.route("/")
    async def handler2(request):
        return text(app2.policy_decision(request, "ratelimit").version_name)

    _, denied = app2.test_client.get(
        "/", headers={"x-tenant-id": "t", "x-policy-version": "v2"}
    )
    assert denied.text == "v1"


# ------------------------------------------------------------ #
# 审计
# ------------------------------------------------------------ #


def test_audit_records_reason_without_credentials(app: Sanic, caplog):
    app, strategy = make_app_with_versions("audit")

    @app.route("/")
    async def handler(request):
        return text("ok")

    with caplog.at_level(logging.INFO, logger="sanic.policy"):
        app.test_client.get(
            "/?token=querysecret",
            headers={
                "x-tenant-id": "acme",
                "Authorization": "Bearer bearersecret",
                "Cookie": "session=cookiesecret",
            },
        )

    records = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "sanic.policy" and r.message.startswith("{")
    ]
    assert records, "expected at least one JSON audit record"
    record = records[0]

    assert record["event"] == "policy.selection"
    assert record["strategy"] == "ratelimit"
    assert record["version"] == "v2"
    assert record["reason"] == "rollout"
    assert record["tenant"] == "acme"
    assert isinstance(record["bucket"], int)
    assert record["path"] == "/"
    assert record["candidates"]

    blob = json.dumps(record)
    for secret in ("bearersecret", "cookiesecret", "querysecret"):
        assert secret not in blob
    assert "token=" not in blob
    assert "Authorization" not in blob
    assert "Cookie" not in blob


def test_audit_records_exemption_reason(app: Sanic, caplog):
    app, strategy = make_app_with_versions("audit-exempt")
    strategy.exempt_tenant("acme")

    @app.route("/")
    async def handler(request):
        return text("ok")

    with caplog.at_level(logging.INFO, logger="sanic.policy"):
        app.test_client.get("/", headers={"x-tenant-id": "acme"})

    records = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "sanic.policy"
    ]
    assert records[-1]["reason"] == "exempt"
    assert records[-1]["version"] == "v1"


# ------------------------------------------------------------ #
# 无策略时零影响与失败开放
# ------------------------------------------------------------ #


def test_no_registry_when_unused(app: Sanic):
    assert app.policy_registry is None
    assert app.policy_decision(None) is None  # type: ignore[arg-type]
    assert len(app.request_middleware) == 0
    assert len(app.response_middleware) == 0


def test_broken_extractor_fails_open(app: Sanic):
    app = Sanic("broken")

    def boom(request):
        raise RuntimeError("extractor down")

    strategy = app.add_policy_strategy("s", tenant_extractor=boom)
    strategy.add_version("v1", fallback=True)
    strategy.add_version("v2", rollout=100, priority=10)

    @app.route("/")
    async def handler(request):
        decision = app.policy_decision(request, "s")
        return text(
            f"{decision.version_name}:{decision.reason.value}"
            if decision
            else "none"
        )

    _, response = app.test_client.get("/")
    assert response.status == 200
    # 选择器故障被安全回退到兜底版本，原因如实标记为 error
    assert response.text == "v1:error"


def test_convenience_add_policy_version_creates_strategy(app: Sanic):
    app.add_policy_version("v1", fallback=True)
    app.add_policy_version("v2", rollout=100, priority=10)

    @app.route("/")
    async def handler(request):
        return text(app.policy_decision(request).version_name)

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.text == "v2"


def test_duplicate_version_and_bad_rollout(app: Sanic):
    app, strategy = make_app_with_versions("dup")
    with pytest.raises(PolicyError):
        strategy.add_version("v2")
    with pytest.raises(PolicyError):
        strategy.add_version("v3", rollout=150)


def test_response_hook_can_replace_response(app: Sanic):
    app, strategy = make_app_with_versions("replace")

    @strategy.on_response("v2")
    async def replace(request, response):
        return sjson({"replaced": True})

    @app.route("/")
    async def handler(request):
        return text("original")

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.status == 200
    assert response.json == {"replaced": True}
    # 新响应同样携带版本标记（lifecycle.response 信号再次标记）
    assert response.headers[VERSION_HEADER] == "ratelimit=v2"


# ------------------------------------------------------------ #
# 多策略与蓝图中间件顺序
# ------------------------------------------------------------ #


def test_multiple_strategies_are_each_frozen_and_marked(app: Sanic):
    app = Sanic("multi")
    rate = app.add_policy_strategy("ratelimit")
    rate.add_version("r1", fallback=True)
    rate.add_version("r2", priority=10, rollout=100)

    auth = app.add_policy_strategy("authz")
    auth.add_version("a1", fallback=True)
    auth.add_version("a2", priority=10, rollout=0)

    @app.route("/")
    async def handler(request):
        return text(
            f"{app.policy_decision(request, 'ratelimit').version_name}/"
            f"{app.policy_decision(request, 'authz').version_name}"
        )

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.text == "r2/a1"
    # 版本头按策略注册顺序排列
    assert response.headers[VERSION_HEADER] == "ratelimit=r2,authz=a1"


def test_blueprint_middleware_order_preserved(app: Sanic):
    from sanic import Blueprint

    app, strategy = make_app_with_versions("bp-order")
    bp = Blueprint("bp")
    order = []

    @app.on_request
    async def app_request(request):
        order.append("app-request")

    @bp.on_request
    async def bp_request(request):
        order.append("bp-request")

    @strategy.on_request("v2")
    async def policy_request(request):
        order.append("policy-request")

    @strategy.on_response("v2")
    async def policy_response(request, response):
        order.append("policy-response")

    @bp.on_response
    async def bp_response(request, response):
        order.append("bp-response")

    @app.on_response
    async def app_response(request, response):
        order.append("app-response")

    @bp.get("/")
    async def handler(request):
        order.append("handler")
        return text("ok")

    app.blueprint(bp)

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.status == 200
    # 版本钩子位于洋葱最内层；蓝图与应用级中间件的既有顺序不变。
    # Sanic 语义：请求阶段 应用 -> 蓝图；响应阶段 应用 -> 蓝图，
    # 因此最内层版本钩子在请求末/响应首执行。
    assert order == [
        "app-request",
        "bp-request",
        "policy-request",
        "handler",
        "policy-response",
        "app-response",
        "bp-response",
    ]


def test_version_marked_even_when_response_middleware_raises(
    app: Sanic, caplog
):
    app, strategy = make_app_with_versions("resp-error")

    @app.on_response
    async def boom_response(request, response):
        raise RuntimeError("response middleware failed")

    @app.route("/")
    async def handler(request):
        return text("ok")

    with caplog.at_level(logging.ERROR):
        _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    # Sanic 会记录响应中间件异常但仍发送原响应；版本标记在
    # http.lifecycle.response 信号上完成，因此最终响应仍确认冻结版本。
    assert response.status == 200
    assert response.headers.get(VERSION_HEADER) == "ratelimit=v2"
    assert "response middleware" in caplog.text or any(
        "Exception occurred in one of response middleware handlers"
        in record.getMessage()
        for record in caplog.records
    )


def test_decision_object_is_frozen_snapshot(app: Sanic):
    app, strategy = make_app_with_versions("snapshot")

    captured = {}

    @app.route("/")
    async def handler(request):
        captured["decision"] = app.policy_decision(request, "ratelimit")
        # 处理过程中立即回退，不影响本次请求已经冻结的决策
        strategy.rollback("v2")
        d = captured["decision"]
        return text(f"{d.version_name}:{d.reason.value}")

    _, response = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response.text == "v2:rollout"
    assert response.headers[VERSION_HEADER] == "ratelimit=v2"

    # 下一个请求则使用回退后的版本
    _, response2 = app.test_client.get("/", headers={"x-tenant-id": "t"})
    assert response2.headers[VERSION_HEADER] == "ratelimit=v1"
