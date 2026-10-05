from __future__ import annotations

import hashlib
import json
import logging
import threading

from collections.abc import Callable
from inspect import isawaitable
from itertools import count
from typing import TYPE_CHECKING, Any

from sanic.strategies.types import (
    DEFAULT_OVERRIDE_HEADER,
    DEFAULT_STRATEGY,
    DEFAULT_VERSION_HEADER,
    ExemptionPredicate,
    IdentityExtractor,
    PolicyConsideration,
    PolicyError,
    PolicyState,
    PolicyVersion,
    SelectionReason,
    StrategyDecision,
    TenantExtractor,
)


if TYPE_CHECKING:
    from sanic.request.types import Request
    from sanic.response.types import BaseHTTPResponse


policy_logger = logging.getLogger("sanic.policy")
"""
策略选择审计日志。只记录版本选择元数据，绝不记录请求凭据。
"""

RequestHook = Callable[["Request"], Any]
ResponseHook = Callable[["Request", "BaseHTTPResponse"], Any]

_BUCKET_MODULUS = 10_000
_TENANT_HEADER = "x-tenant-id"
_IDENTITY_HEADER = "x-user-id"


def _default_tenant_extractor(request: "Request") -> str | None:
    return request.headers.getone(_TENANT_HEADER, None)


def _default_identity_extractor(request: "Request") -> str | None:
    return request.headers.getone(_IDENTITY_HEADER, None)


def stable_bucket(strategy: str, key: str) -> int:
    """把 ``(策略, 稳定键)`` 哈希到 ``[0, 9999]`` 的稳定分桶。

    同一租户/身份始终落入同一桶；调大灰度比例只会抬高阈值，不会让已经
    命中的桶丢失，因此灰度扩量是单调的。
    """
    digest = hashlib.sha256(f"{strategy}:{key}".encode()).hexdigest()
    return int(digest[:8], 16) % _BUCKET_MODULUS


class PolicyStrategy:
    """一组可版本化的策略。

    线程安全：注册、调比例、回退都可以在运行时进行，并立即对之后进入的
    请求生效；已经做出选择的请求持有的是冻结快照，不受影响。
    """

    def __init__(
        self,
        name: str,
        *,
        tenant_extractor: TenantExtractor | None = None,
        identity_extractor: IdentityExtractor | None = None,
        override_header: str | None = DEFAULT_OVERRIDE_HEADER,
        allow_override: bool = False,
    ) -> None:
        self.name = name
        self.tenant_extractor = tenant_extractor or _default_tenant_extractor
        self.identity_extractor = (
            identity_extractor or _default_identity_extractor
        )
        self.override_header = override_header
        self.allow_override = allow_override

        self._versions: dict[str, PolicyVersion] = {}
        self._order: list[str] = []
        self._definition = count()
        self._exemptions: list[ExemptionPredicate] = []
        self._exempt_tenants: set[str] = set()
        self._request_hooks: dict[str, list[RequestHook]] = {}
        self._response_hooks: dict[str, list[ResponseHook]] = {}
        self._lock = threading.RLock()
        self._revision = 0
        self._disabled: bool = False

    # ------------------------------------------------------------------ #
    # 版本管理
    # ------------------------------------------------------------------ #

    def add_version(
        self,
        name: str,
        payload: Any = None,
        *,
        priority: int = 0,
        rollout: float = 0.0,
        fallback: bool = False,
        exempt: bool = False,
        tenants: "frozenset[str] | set[str] | None" = None,
        enabled: bool = True,
    ) -> PolicyVersion:
        """注册一个新版本。

        :param name: 版本名，在策略内唯一
        :param payload: 挂在版本上的任意策略对象；注册后视为不可变，
            需要调整时请注册新版本，而不是就地修改
        :param priority: 版本优先级，数值越大越优先评估
        :param rollout: 灰度比例，``0~100``
        :param fallback: 是否为兜底版本（现行策略），全策略只能有一个
        :param exempt: 是否为豁免版本，命中豁免规则时使用
        :param tenants: 显式固定到该版本的租户集合（不受灰度比例限制）
        :param enabled: 注册后是否立即可用
        """
        self._validate_rollout(rollout)
        with self._lock:
            if name in self._versions:
                raise PolicyError(
                    f"Policy version {name!r} already exists for strategy "
                    f"{self.name!r}"
                )
            if fallback and self._fallback_locked() not in (None, name):
                raise PolicyError(
                    f"Strategy {self.name!r} already has a fallback version "
                    f"{self._fallback_locked()!r}"
                )
            version = PolicyVersion(
                name=name,
                payload=payload,
                priority=priority,
                rollout=rollout,
                enabled=enabled,
                fallback=fallback,
                exempt=exempt,
                allowed_tenants=(
                    frozenset(tenants) if tenants is not None else None
                ),
                definition=next(self._definition),
            )
            self._versions[name] = version
            self._order.append(name)
            self._bump()
            return version

    def set_rollout(self, name: str, rollout: float) -> PolicyVersion:
        """调整灰度比例（百分比），立即对后续请求生效。"""
        self._validate_rollout(rollout)
        with self._lock:
            version = self._get_locked(name)
            version.rollout = rollout
            version.revision += 1
            self._bump()
            return version

    def enable(self, name: str) -> PolicyVersion:
        """项目内部接口说明。"""
        with self._lock:
            version = self._get_locked(name)
            version.enabled = True
            if version.state is PolicyState.DISABLED:
                version.state = PolicyState.ENABLED
            version.revision += 1
            self._bump()
            return version

    def disable(self, name: str) -> PolicyVersion:
        """项目内部接口说明。"""
        with self._lock:
            version = self._get_locked(name)
            version.enabled = False
            version.state = PolicyState.DISABLED
            version.revision += 1
            self._bump()
            return version

    def rollback(self, name: str | None = None) -> None:
        """立即回退。

        - 传入版本名：只把该版本标记为已回退，后续请求不再选中它；
        - 不传：回退整个策略，所有新版本停用，请求全部回到兜底版本。

        对已经进入处理流程的请求无效——它们从进入时起就锁定了版本，
        这正是“一次请求始终使用同一版本”的保证。
        """
        with self._lock:
            if name is None:
                self._disabled = True
                for version in self._versions.values():
                    if not version.fallback:
                        version.state = PolicyState.ROLLED_BACK
                self._bump()
                return
            version = self._get_locked(name)
            version.state = PolicyState.ROLLED_BACK
            version.enabled = False
            version.revision += 1
            self._bump()

    def restore(self, name: str | None = None) -> None:
        """撤销回退（与 :meth:`rollback` 对应）。"""
        with self._lock:
            if name is None:
                self._disabled = False
                for version in self._versions.values():
                    if version.state is PolicyState.ROLLED_BACK:
                        version.state = PolicyState.ENABLED
                        version.enabled = True
                        version.revision += 1
                self._bump()
                return
            version = self._get_locked(name)
            if version.state is PolicyState.ROLLED_BACK:
                version.state = PolicyState.ENABLED
                version.enabled = True
                version.revision += 1
            self._bump()

    # ------------------------------------------------------------------ #
    # 豁免
    # ------------------------------------------------------------------ #

    def exempt_tenant(self, *tenants: str) -> None:
        """显式豁免一个或多个租户：始终走豁免/兜底版本。"""
        with self._lock:
            self._exempt_tenants.update(tenants)
            self._bump()

    def add_exemption(
        self, predicate: ExemptionPredicate
    ) -> ExemptionPredicate:
        """注册豁免判定函数 ``(request, tenant) -> bool``，可为协程。"""
        with self._lock:
            self._exemptions.append(predicate)
            self._bump()
        return predicate

    # ------------------------------------------------------------------ #
    # 版本执行钩子
    # ------------------------------------------------------------------ #

    def on_request(
        self, version_name: str
    ) -> Callable[[RequestHook], RequestHook]:
        """把请求中间件逻辑绑定到某个版本，仅该版本被选中时执行。"""

        def decorator(func: RequestHook) -> RequestHook:
            with self._lock:
                self._request_hooks.setdefault(version_name, []).append(func)
            return func

        return decorator

    def on_response(
        self, version_name: str
    ) -> Callable[[ResponseHook], ResponseHook]:
        """把响应中间件逻辑绑定到某个版本，仅该版本被选中时执行。"""

        def decorator(func: ResponseHook) -> ResponseHook:
            with self._lock:
                self._response_hooks.setdefault(version_name, []).append(func)
            return func

        return decorator

    def request_hooks(self, version_name: str) -> list[RequestHook]:
        """项目内部接口说明。"""
        return list(self._request_hooks.get(version_name, ()))

    def response_hooks(self, version_name: str) -> list[ResponseHook]:
        """项目内部接口说明。"""
        return list(self._response_hooks.get(version_name, ()))

    # ------------------------------------------------------------------ #
    # 选择
    # ------------------------------------------------------------------ #

    async def select(self, request: "Request") -> StrategyDecision:
        """为本次请求选择并冻结一个版本。"""
        tenant = self.tenant_extractor(request)
        identity = self.identity_extractor(request)
        considerations: list[PolicyConsideration] = []

        with self._lock:
            # 在锁内一次性取得配置快照，选择过程不与运行时变更竞争
            fallback = self._fallback_locked()
            exempt_version = self._exempt_version_locked()
            versions = self._ordered_candidates_locked()
            exempt_tenants = frozenset(self._exempt_tenants)
            exemptions = tuple(self._exemptions)
            versions_by_name = dict(self._versions)

        # 1) 显式豁免（最高优先级）：豁免租户或豁免谓词命中
        if tenant and tenant in exempt_tenants:
            decision = self._decision(
                self._exempt_or_fallback(
                    exempt_version, fallback, versions_by_name
                ),
                SelectionReason.EXEMPT,
                tenant,
                None,
                considerations,
            )
            considerations.append(self._consider(decision, "exempt_tenant"))
            return decision

        for predicate in exemptions:
            try:
                matched = predicate(request, tenant)
                if isawaitable(matched):
                    matched = await matched
            except Exception:  # noqa: BLE001
                policy_logger.exception(
                    "Policy exemption predicate raised; treating as not exempt"
                )
                matched = False
            if matched:
                chosen = self._exempt_or_fallback(
                    exempt_version, fallback, versions_by_name
                )
                decision = self._decision(
                    chosen,
                    SelectionReason.EXEMPT,
                    tenant,
                    None,
                    considerations,
                )
                considerations.append(
                    self._consider(decision, "exempt_predicate")
                )
                return decision

        # 2) 调用方显式指定版本（仅在策略允许时）
        if self.allow_override and self.override_header:
            requested = request.headers.getone(self.override_header, None)
            candidate = versions_by_name.get(requested) if requested else None
            if candidate is not None and candidate.available:
                considerations.append(
                    PolicyConsideration(
                        version=candidate.name,
                        selected=True,
                        reason=SelectionReason.OVERRIDE.value,
                        rollout=candidate.rollout,
                        bucket=None,
                    )
                )
                return self._decision(
                    candidate,
                    SelectionReason.OVERRIDE,
                    tenant,
                    None,
                    considerations,
                )

        # 稳定分桶键：租户优先，其次身份；都没有时退回到请求 ID，
        # 仍然保证同一请求的决策稳定（且不使用任何凭据做分桶）。
        bucket_key = tenant or identity or str(request.id)
        bucket = stable_bucket(self.name, bucket_key)

        # 3) 按优先级依次评估：租户固定优先于灰度比例
        for version in versions:
            if not version.available or version.fallback:
                continue
            if (
                version.allowed_tenants is not None
                and tenant in version.allowed_tenants
            ):
                considerations.append(
                    PolicyConsideration(
                        version=version.name,
                        selected=True,
                        reason=SelectionReason.PINNED.value,
                        rollout=version.rollout,
                        bucket=bucket,
                    )
                )
                return self._decision(
                    version,
                    SelectionReason.PINNED,
                    tenant,
                    bucket,
                    considerations,
                )
            if version.rollout > 0:
                threshold = int(version.rollout * _BUCKET_MODULUS / 100)
                selected = bucket < threshold
                considerations.append(
                    PolicyConsideration(
                        version=version.name,
                        selected=selected,
                        reason=SelectionReason.ROLLOUT.value,
                        rollout=version.rollout,
                        bucket=bucket,
                    )
                )
                if selected:
                    return self._decision(
                        version,
                        SelectionReason.ROLLOUT,
                        tenant,
                        bucket,
                        considerations,
                    )

        # 4) 兜底
        chosen = versions_by_name.get(fallback) if fallback else None
        reason = SelectionReason.FALLBACK if chosen else SelectionReason.NONE
        return self._decision(chosen, reason, tenant, bucket, considerations)

    def failure_decision(self) -> StrategyDecision:
        """选择过程异常时的安全决策：回退到兜底版本（若存在）。"""
        with self._lock:
            fallback = self._fallback_locked()
            chosen = self._versions.get(fallback) if fallback else None
        return self._decision(chosen, SelectionReason.ERROR, None, None, [])

    # ------------------------------------------------------------------ #
    # 观察
    # ------------------------------------------------------------------ #

    @property
    def revision(self) -> int:
        """策略配置的单调修订号，每次变更递增。"""
        return self._revision

    @property
    def disabled(self) -> bool:
        """项目内部接口说明。"""
        return self._disabled

    @property
    def versions(self) -> tuple[PolicyVersion, ...]:
        """项目内部接口说明。"""
        with self._lock:
            return tuple(self._versions[n] for n in self._order)

    def snapshot(self) -> dict[str, Any]:
        """供审计/排障使用的配置快照（不含任何请求数据）。"""
        with self._lock:
            return {
                "strategy": self.name,
                "disabled": self._disabled,
                "revision": self._revision,
                "versions": [
                    {
                        "version": v.name,
                        "priority": v.priority,
                        "rollout": v.rollout,
                        "enabled": v.enabled,
                        "state": v.state.value,
                        "fallback": v.fallback,
                        "exempt": v.exempt,
                        "tenants": (
                            sorted(v.allowed_tenants)
                            if v.allowed_tenants is not None
                            else None
                        ),
                        "revision": v.revision,
                    }
                    for v in (self._versions[n] for n in self._order)
                ],
            }

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #

    def _bump(self) -> None:
        self._revision += 1

    def _exempt_or_fallback(
        self,
        exempt_version: PolicyVersion | None,
        fallback: str | None,
        versions_by_name: dict[str, PolicyVersion],
    ) -> PolicyVersion | None:
        if exempt_version is not None and exempt_version.available:
            return exempt_version
        return versions_by_name.get(fallback) if fallback else None

    def _get_locked(self, name: str) -> PolicyVersion:
        try:
            return self._versions[name]
        except KeyError:
            raise PolicyError(
                f"Unknown policy version {name!r} for strategy {self.name!r}"
            ) from None

    def _fallback_locked(self) -> str | None:
        return next(
            (n for n in self._order if self._versions[n].fallback),
            None,
        )

    def _exempt_version_locked(self) -> PolicyVersion | None:
        return next(
            (
                self._versions[n]
                for n in self._order
                if self._versions[n].exempt
            ),
            None,
        )

    def _ordered_candidates_locked(self) -> list[PolicyVersion]:
        return sorted(
            (self._versions[n] for n in self._order),
            key=lambda v: (v.priority, v.definition),
            reverse=True,
        )

    def _decision(
        self,
        version: PolicyVersion | None,
        reason: SelectionReason,
        tenant: str | None,
        bucket: int | None,
        considerations: list[PolicyConsideration],
    ) -> StrategyDecision:
        return StrategyDecision(
            strategy=self.name,
            version=version,
            reason=reason,
            exempt=reason is SelectionReason.EXEMPT,
            bucket=bucket,
            tenant=tenant,
            considerations=tuple(considerations),
        )

    def _consider(
        self, decision: StrategyDecision, detail: str
    ) -> PolicyConsideration:
        return PolicyConsideration(
            version=decision.version_name or "",
            selected=True,
            reason=f"{decision.reason.value}:{detail}",
            rollout=decision.version.rollout if decision.version else 0.0,
            bucket=decision.bucket,
        )

    @staticmethod
    def _validate_rollout(rollout: float) -> None:
        if not 0.0 <= rollout <= 100.0:
            raise PolicyError("rollout must be between 0 and 100")


class PolicyRegistry:
    """应用级策略注册表：持有多组策略，并负责请求级冻结与执行。"""

    def __init__(self, version_header: str = DEFAULT_VERSION_HEADER) -> None:
        self._strategies: dict[str, PolicyStrategy] = {}
        self._lock = threading.RLock()
        self.version_header = version_header

    def add(
        self,
        name: str = DEFAULT_STRATEGY,
        *,
        tenant_extractor: TenantExtractor | None = None,
        identity_extractor: IdentityExtractor | None = None,
        override_header: str | None = DEFAULT_OVERRIDE_HEADER,
        allow_override: bool = False,
    ) -> PolicyStrategy:
        """新增一组策略，名称在应用内唯一。"""
        with self._lock:
            if name in self._strategies:
                raise PolicyError(f"Strategy {name!r} already exists")
            strategy = PolicyStrategy(
                name,
                tenant_extractor=tenant_extractor,
                identity_extractor=identity_extractor,
                override_header=override_header,
                allow_override=allow_override,
            )
            self._strategies[name] = strategy
            return strategy

    def get(self, name: str = DEFAULT_STRATEGY) -> PolicyStrategy:
        """项目内部接口说明。"""
        try:
            return self._strategies[name]
        except KeyError:
            raise PolicyError(f"Unknown strategy {name!r}") from None

    @property
    def strategies(self) -> tuple[PolicyStrategy, ...]:
        """项目内部接口说明。"""
        with self._lock:
            return tuple(self._strategies.values())

    async def resolve(self, request: "Request") -> dict[str, StrategyDecision]:
        """请求进入时调用一次：为每组策略做出并冻结决策。

        决策同时写入 ``request._policy_decisions``，之后整个生命周期
        （异常处理、响应阶段）都只能读取这份冻结结果。

        单组策略选择失败不会拖垮整站：该组安全回退到其兜底版本
        （无兜底版本时为“无版本”），原因以 ``error`` 如实记入审计，
        其它策略照常选择。
        """
        decisions: dict[str, StrategyDecision] = {}
        for strategy in self.strategies:
            try:
                decision = await strategy.select(request)
            except Exception:  # noqa: BLE001
                # 选择过程失败（如租户提取器异常）时安全回退到兜底版本，
                # 不让策略基础设施故障扩大成整站故障；原因如实记入审计。
                policy_logger.exception(
                    "Policy selection failed; failing safe on the fallback "
                    "version for strategy %r",
                    strategy.name,
                )
                decision = strategy.failure_decision()
            decisions[strategy.name] = decision
            self._audit(request, strategy, decision)
        request._policy_decisions = decisions
        return decisions

    def decision_for(
        self, request: "Request", name: str = DEFAULT_STRATEGY
    ) -> StrategyDecision | None:
        """读取请求冻结的决策；尚未解析或策略不存在时返回 ``None``。"""
        decisions = request._policy_decisions
        if decisions is None:
            return None
        return decisions.get(name)

    def mark_response(
        self, request: "Request", response: "BaseHTTPResponse"
    ) -> None:
        """在最终响应上标记本次冻结的版本。

        在 ``http.lifecycle.response`` 阶段（响应头发送前）调用：
        即使响应中间件替换过响应对象、或请求走了异常处理重建响应，
        最终发出的响应也能确认本次实际使用的版本。
        """
        decisions = request._policy_decisions
        if decisions is None:
            return
        self._mark_response(decisions, response)

    async def run_request_hooks(self, request: "Request") -> Any:
        """按版本优先级执行被选中版本的请求钩子。

        钩子返回响应对象时短路（与普通请求中间件语义一致）。
        """
        decisions = request._policy_decisions
        if decisions is None:
            return None
        for strategy in self._strategies_priority(decisions):
            decision = decisions[strategy.name]
            if decision.version is None:
                continue
            for hook in strategy.request_hooks(decision.version.name):
                result = hook(request)
                if isawaitable(result):
                    result = await result
                if result:
                    return result
        return None

    async def run_response_hooks(
        self, request: "Request", response: "BaseHTTPResponse"
    ) -> "BaseHTTPResponse":
        """执行被选中版本的响应钩子。

        版本标记在 ``http.lifecycle.response`` 阶段单独完成，这里只执行
        版本自己的响应逻辑；策略间按注册逆序执行，与请求阶段对称。
        """
        decisions = request._policy_decisions
        if decisions is None:
            return response
        for strategy in self._strategies_priority(decisions, reverse=True):
            decision = decisions[strategy.name]
            if decision.version is None:
                continue
            for hook in strategy.response_hooks(decision.version.name):
                result = hook(request, response)
                if isawaitable(result):
                    result = await result
                if result:
                    # 与普通响应中间件语义一致：返回响应即替换并结束钩子链
                    return result
        return response

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #

    def _strategies_priority(
        self,
        decisions: dict[str, StrategyDecision],
        *,
        reverse: bool = False,
    ) -> list[PolicyStrategy]:
        # 策略间顺序以注册顺序为准，行为可预测；响应阶段逆序执行，
        # 与 Sanic 现有请求/响应中间件的洋葱模型保持一致。
        ordered = [s for s in self.strategies if s.name in decisions]
        return list(reversed(ordered)) if reverse else ordered

    def _mark_response(
        self,
        decisions: dict[str, StrategyDecision],
        response: "BaseHTTPResponse",
    ) -> None:
        chosen = {
            name: decision.version_name or ""
            for name, decision in decisions.items()
        }
        if not chosen:
            return
        value = ",".join(
            f"{name}={version}" for name, version in chosen.items()
        )
        try:
            response.headers[self.version_header] = value
        except Exception:  # noqa: BLE001
            policy_logger.exception(
                "Failed to mark policy version on response"
            )

    def _audit(
        self,
        request: "Request",
        strategy: PolicyStrategy,
        decision: StrategyDecision,
    ) -> None:
        """记录选择原因。

        安全约束：只记录方法、路径（不含查询串）、请求 ID、租户标识、
        分桶与原因等选择元数据；不记录任何请求头、Cookie、凭据或请求体。
        """
        try:
            record = {
                "event": "policy.selection",
                "request_id": str(request.id),
                "method": request.method,
                "path": request.path,
                "strategy": strategy.name,
                "version": decision.version_name,
                "reason": decision.reason.value,
                "exempt": decision.exempt,
                "tenant": decision.tenant,
                "bucket": decision.bucket,
                "rollout": (
                    decision.version.rollout if decision.version else None
                ),
                "candidates": [
                    {
                        "version": c.version,
                        "selected": c.selected,
                        "reason": c.reason,
                        "bucket": c.bucket,
                    }
                    for c in decision.considerations
                ],
                "strategy_revision": strategy.revision,
            }
            policy_logger.info(json.dumps(record, default=str, sort_keys=True))
        except Exception:  # noqa: BLE001
            policy_logger.exception("Failed to write policy audit record")


def assert_no_credentials_in_audit_text(text: str) -> None:
    """测试辅助：断言一段审计文本不含常见凭据泄露。"""
    lowered = text.lower()
    for marker in ("authorization:", "cookie:", "set-cookie:", "bearer "):
        assert marker not in lowered
