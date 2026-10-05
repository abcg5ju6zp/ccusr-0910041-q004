"""可版本化策略的选择与执行机制。

设计目标见 ``PolicyRegistry`` 的文档字符串：一次请求只在进入时做一次
版本选择，之后请求中间件、处理器、异常处理、响应中间件都使用同一版本，
中间即使调整灰度比例或执行回退也不影响在途请求。
"""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from enum import IntEnum
from hashlib import blake2b
from itertools import count
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Iterable,
)

from sanic.policies.reasons import SelectionReason
from sanic.policies.rollout import BUCKET_SPACE, Rollout


if TYPE_CHECKING:
    from sanic.request import Request

#: 写入审计记录 / 响应头时使用的键名
POLICY_VERSION_HEADER = "x-policy-version"

#: 审计记录中永不出现的请求头片段（小写子串匹配）
_SENSITIVE_FRAGMENTS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "credential",
    "password",
    "proxy-authorization",
    "set-cookie",
    "api-key",
    "apikey",
)


class PolicyPhase(IntEnum):
    """策略钩子在请求生命周期中的位置。

    数值即执行顺序：一个版本在四个阶段都会被询问，
    但在途请求始终使用进入时选定的同一个版本对象。
    """

    REQUEST = 10
    EXCEPTION = 20
    RESPONSE = 30
    COMPLETE = 40


#: 钩子签名：``async def hook(request, ...)``，
#: 返回响应则短路（EXCEPTION 阶段除外）
PolicyHook = Callable[..., Any]


@dataclass(frozen=True)
class PolicyVersion:
    """一个不可变的策略版本。

    :param name: 版本标识，如 ``"v1"``、``"v2"``
    :param priority: 规则匹配时的优先级，数值越大越优先
    :param rollout: 灰度规则；缺省为 100% 全开
    :param on_request: 请求阶段钩子（同 Sanic 请求中间件语义，
        可返回响应短路）
    :param on_exception: 异常阶段钩子，可观测或替换/抑制异常返回的响应
    :param on_response: 响应阶段钩子（同 Sanic 响应中间件语义）
    :param on_complete: 响应结束后的观测钩子（仅观测，返回值被忽略）
    :param metadata: 随审计记录一起导出的非敏感元数据
    """

    name: str
    priority: int = 0
    rollout: Rollout = field(default_factory=lambda: Rollout(100.0))
    on_request: PolicyHook | None = None
    on_exception: PolicyHook | None = None
    on_response: PolicyHook | None = None
    on_complete: PolicyHook | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("PolicyVersion.name 必须是非空字符串")
        if not isinstance(self.rollout, Rollout):
            raise TypeError("rollout 必须是 Rollout 实例")

    def hook(self, phase: PolicyPhase) -> PolicyHook | None:
        return {
            PolicyPhase.REQUEST: self.on_request,
            PolicyPhase.EXCEPTION: self.on_exception,
            PolicyPhase.RESPONSE: self.on_response,
            PolicyPhase.COMPLETE: self.on_complete,
        }[phase]


@dataclass(frozen=True)
class _Rule:
    """一条租户/豁免/灰度匹配规则，与某个候选版本绑定。"""

    version: PolicyVersion
    tenants: frozenset[str]
    exempt: bool
    definition: int

    def matches_tenant(self, tenant: str | None) -> bool:
        return (
            bool(self.tenants)
            and tenant is not None
            and tenant in self.tenants
        )


@dataclass(frozen=True)
class PolicySelection:
    """一次请求的版本选择结果，在整个请求生命周期内不可变。"""

    registry: str
    version: PolicyVersion | None
    reason: SelectionReason
    bucket: int | None
    tenant: str | None
    rule_priority: int | None = None
    matched: bool = False
    error: str | None = None

    @property
    def version_name(self) -> str | None:
        return self.version.name if self.version else None

    def audit(self) -> dict[str, Any]:
        """生成可安全落盘的审计记录。

        只包含选择原因和版本元数据，不包含任何请求内容
        （无 URL、无头、无 Cookie、无凭据）。
        """
        record: dict[str, Any] = {
            "registry": self.registry,
            "version": self.version_name,
            "reason": self.reason.value,
            "tenant": self.tenant,
            "bucket": self.bucket,
            "priority": self.rule_priority,
        }
        if self.version is not None:
            # 只暴露标量元数据，避免调用方意外把请求对象塞进来
            record["metadata"] = {
                key: value
                for key, value in self.version.metadata.items()
                if _is_safe_metadata(value)
            }
        if self.error:
            record["error"] = self.error
        return record


def _is_safe_metadata(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def stable_bucket(registry: str, key: str) -> int:
    """把稳定身份哈希到 ``[0, BUCKET_SPACE)``。

    使用加 salt 的 BLAKE2b：同一身份在同一注册表上永远落在同一桶，
    且不同注册表之间互不相关。
    """

    digest = blake2b(
        f"{registry}:{key}".encode("utf-8"),
        digest_size=8,
        person=b"policy",
    ).digest()
    return int.from_bytes(digest, "big") % BUCKET_SPACE


class PolicyRegistry:
    """持有一个策略家族的全部版本，并为每个请求做一次版本选择。

    用法::

        registry = app.ctx.policies = PolicyRegistry("request-security")
        registry.add(v1)                       # 基线版本
        registry.add(v2, tenants={"acme"})     # 灰度新版本
        registry.set_default("v1")             # 未命中规则时的兜底版本
        registry.canary("v2", percentage=25.0) # 把 acme 调整为 25%
        registry.rollback("v1")                # 立即回退

    选择优先级（从高到低）：

    1. 显式豁免规则（``exempt=True``）
    2. 显式钉版（``pinned_version``，如内部调试头解析结果）
    3. 租户规则，按版本 ``priority`` 降序、注册顺序决胜
    4. 默认版本
    """

    def __init__(self, name: str) -> None:
        if not name:
            raise ValueError("PolicyRegistry 必须有名字")
        self.name = name
        self._versions: dict[str, PolicyVersion] = {}
        self._rules: list[_Rule] = []
        self._default_name: str | None = None
        self._rule_counter = count()

    # ------------------------------------------------------------------ #
    # 配置（运行期可随时调用，对在途请求无影响——它们持有不可变选择结果）
    # ------------------------------------------------------------------ #

    def add(
        self,
        version: PolicyVersion,
        *,
        tenants: Iterable[str] | None = None,
        exempt: bool = False,
        make_default: bool = False,
    ) -> PolicyVersion:
        """注册一个版本；可选附带一条租户规则或豁免规则。"""

        if version.name in self._versions:
            raise ValueError(
                f"策略版本 {version.name!r} 已存在于 {self.name!r}"
            )
        self._versions[version.name] = version
        if tenants is not None or exempt:
            self._rules.append(
                _Rule(
                    version=version,
                    tenants=frozenset(tenants or ()),
                    exempt=exempt,
                    definition=next(self._rule_counter),
                )
            )
        if make_default or self._default_name is None:
            self._default_name = version.name
        return version

    def exempt(
        self,
        version_name: str,
        tenants: Iterable[str] | None = None,
    ) -> None:
        """为已注册版本追加一条显式豁免规则（优先级高于灰度）。"""

        version = self._require(version_name)
        self._rules.append(
            _Rule(
                version=version,
                tenants=frozenset(tenants or ()),
                exempt=True,
                definition=next(self._rule_counter),
            )
        )

    def set_default(self, version_name: str) -> None:
        self._require(version_name)
        self._default_name = version_name

    def canary(
        self,
        version_name: str,
        percentage: float,
        *,
        key: str | None = None,
        tenants: Iterable[str] | None = None,
    ) -> None:
        """调整某版本的灰度比例（立即生效，仅影响之后的新选择）。

        也可借 ``key`` 钉住一组确定身份做内部验证，或用 ``tenants``
        把比例限定在部分租户上。
        """

        version = self._require(version_name)
        version.rollout.update(percentage, key=key)
        if tenants is not None:
            self._rules.append(
                _Rule(
                    version=version,
                    tenants=frozenset(tenants),
                    exempt=False,
                    definition=next(self._rule_counter),
                )
            )

    def rollback(self, version_name: str | None = None) -> None:
        """立即回退：把默认版本切回 ``version_name``（默认即当前默认），
        并将所有非豁免版本的灰度比例置零。

        在途请求仍使用各自选定的版本走完生命周期；新请求全部落到默认版本。
        """

        if version_name is not None:
            self.set_default(version_name)
        for version in self._versions.values():
            version.rollout.update(0.0)

    @property
    def default(self) -> PolicyVersion | None:
        if self._default_name is None:
            return None
        return self._versions.get(self._default_name)

    def get(self, version_name: str) -> PolicyVersion:
        return self._require(version_name)

    def _require(self, version_name: str) -> PolicyVersion:
        try:
            return self._versions[version_name]
        except KeyError:
            raise ValueError(
                f"策略版本 {version_name!r} 未注册到 {self.name!r}"
            ) from None

    # ------------------------------------------------------------------ #
    # 选择
    # ------------------------------------------------------------------ #

    def select(
        self,
        request: Request | None = None,
        *,
        tenant: str | None = None,
        identity: str | None = None,
        pinned_version: str | None = None,
        exempt: bool = False,
    ) -> PolicySelection:
        """为一次请求选择版本。纯同步、无副作用，可安全用于测试。"""

        if not self._versions:
            return PolicySelection(
                registry=self.name,
                version=None,
                reason=SelectionReason.UNCONFIGURED,
                bucket=None,
                tenant=tenant,
            )

        # 1) 显式豁免：调用方判定（如路径白名单）或命中豁免租户规则
        if exempt:
            return self._exempt_selection(
                tenant, reason=SelectionReason.EXEMPT
            )
        exempt_rule = self._rule_for_tenant(tenant, want_exempt=True)
        if exempt_rule is not None:
            return PolicySelection(
                registry=self.name,
                version=exempt_rule.version,
                reason=SelectionReason.EXEMPT,
                bucket=None,
                tenant=tenant,
                rule_priority=exempt_rule.version.priority,
                matched=True,
            )

        # 2) 显式钉版（由调用方从受信头解析，注册表本身不读请求凭据）
        if pinned_version and pinned_version in self._versions:
            return PolicySelection(
                registry=self.name,
                version=self._versions[pinned_version],
                reason=SelectionReason.PINNED,
                bucket=None,
                tenant=tenant,
                rule_priority=self._versions[pinned_version].priority,
                matched=True,
            )

        # 3) 租户规则 + 稳定分桶灰度
        rule = self._rule_for_tenant(tenant, want_exempt=False)
        if rule is not None:
            rollout = rule.version.rollout
            # 优先使用细粒度身份；缺省时退化为按租户整桶灰度，
            # 同一租户在同一比例下永远得到一致结果。
            key = rollout.key or identity or tenant
            bucket = stable_bucket(self.name, key)
            if rollout.includes(bucket):
                return PolicySelection(
                    registry=self.name,
                    version=rule.version,
                    reason=SelectionReason.CANARY_INCLUDED,
                    bucket=bucket,
                    tenant=tenant,
                    rule_priority=rule.version.priority,
                    matched=True,
                )
            return PolicySelection(
                registry=self.name,
                version=self.default,
                reason=SelectionReason.CANARY_EXCLUDED,
                bucket=bucket,
                tenant=tenant,
                rule_priority=rule.version.priority,
                matched=False,
            )

        # 4) 默认版本
        return self._default_selection(tenant, bucket=None)

    def _exempt_selection(
        self, tenant: str | None, *, reason: SelectionReason
    ) -> PolicySelection:
        return PolicySelection(
            registry=self.name,
            version=self.default,
            reason=reason,
            bucket=None,
            tenant=tenant,
            rule_priority=self.default.priority if self.default else None,
            matched=True,
        )

    def _default_selection(
        self,
        tenant: str | None,
        *,
        bucket: int | None,
        error: str | None = None,
    ) -> PolicySelection:
        return PolicySelection(
            registry=self.name,
            version=self.default,
            reason=SelectionReason.DEFAULT,
            bucket=bucket,
            tenant=tenant,
            rule_priority=self.default.priority if self.default else None,
            matched=False,
            error=error,
        )

    def _rule_for_tenant(
        self, tenant: str | None, *, want_exempt: bool
    ) -> _Rule | None:
        candidates = [
            rule
            for rule in self._rules
            if rule.exempt is want_exempt and rule.matches_tenant(tenant)
        ]
        if not candidates:
            return None
        # 优先级降序；同优先级先注册者胜出（definition 升序）
        return min(
            candidates,
            key=lambda r: (-r.version.priority, r.definition),
        )


_SAFE_TENANT_RE = re.compile(r"[^A-Za-z0-9_.@\-]")


def sanitize_tenant(value: str | None) -> str | None:
    """把租户标识收敛到安全字符集，供审计/分桶使用。"""

    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return _SAFE_TENANT_RE.sub("?", value)[:128]


def redact_headers(headers: Any) -> dict[str, str]:
    """工具函数：导出请求头时剔除所有凭据类头。

    审计记录默认不导出请求头；确需调试时应使用本函数。
    """

    redacted: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        return redacted
    for name, value in items:
        lowered = name.lower()
        if any(fragment in lowered for fragment in _SENSITIVE_FRAGMENTS):
            continue
        redacted[name] = value
    return redacted
