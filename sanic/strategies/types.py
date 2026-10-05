from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from sanic.exceptions import SanicException


if TYPE_CHECKING:
    from sanic.request.types import Request


#: 默认策略名称。一个应用可以同时拥有多组相互独立的策略，
#: 未显式指定名称时使用该名称。
DEFAULT_STRATEGY = "default"

#: 请求方强制指定版本的请求头，仅在策略显式开启 ``allow_override`` 时生效。
DEFAULT_OVERRIDE_HEADER = "x-policy-version"

#: 响应阶段回写给调用方、用于确认本次请求实际使用版本的响应头。
DEFAULT_VERSION_HEADER = "X-Policy-Version"

TenantExtractor = Callable[["Request"], str | None]
IdentityExtractor = Callable[["Request"], str | None]
ExemptionPredicate = Callable[
    ["Request", str | None], "bool | Awaitable[bool]"
]


class PolicyError(SanicException):
    """策略版本注册或选择过程中的配置错误。"""


class SelectionReason(str, Enum):
    """版本被选中（或未选中）的原因，用于审计记录。"""

    #: 命中灰度比例
    ROLLOUT = "rollout"
    #: 租户/身份被显式固定到某版本
    PINNED = "pinned"
    #: 调用方通过请求头显式指定，且策略开启了允许覆盖
    OVERRIDE = "override"
    #: 该版本被标记为豁免版本（兜底的现行策略），请求命中豁免规则
    EXEMPT = "exempt"
    #: 没有任何候选版本命中，使用兜底版本
    FALLBACK = "fallback"
    #: 选择过程本身出错（如租户提取器异常），安全回退到兜底版本
    ERROR = "error"
    #: 策略中不存在任何可用版本
    NONE = "none"


class PolicyState(str, Enum):
    """版本的生命周期状态。"""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ROLLED_BACK = "rolled_back"


@dataclass(slots=True)
class PolicyVersion:
    """一个不可替换、就地演进的策略版本。

    灰度比例等字段可以随时调整并立即对后续请求生效；已经选定版本的请求
    会一直持有同一个对象，不会受到调整影响。
    """

    name: str
    payload: Any = None
    priority: int = 0
    rollout: float = 0.0
    enabled: bool = True
    fallback: bool = False
    exempt: bool = False
    allowed_tenants: frozenset[str] | None = None
    definition: int = 0
    revision: int = 0
    state: PolicyState = PolicyState.ENABLED

    @property
    def available(self) -> bool:
        """项目内部接口说明。"""
        return self.enabled and self.state is not PolicyState.ROLLED_BACK


@dataclass(frozen=True, slots=True)
class PolicyConsideration:
    """单个候选版本在本次选择中的评估记录。"""

    version: str
    selected: bool
    reason: str
    rollout: float
    bucket: int | None


@dataclass(frozen=True, slots=True)
class StrategyDecision:
    """一次请求针对某组策略的冻结决策。

    决策在请求进入时计算一次，随后在中间件、处理器、异常处理和响应阶段
    始终返回同一份结果，保证一次请求从头到尾使用同一版本。
    """

    strategy: str
    version: PolicyVersion | None
    reason: SelectionReason
    exempt: bool
    bucket: int | None
    tenant: str | None
    considerations: tuple[PolicyConsideration, ...] = field(
        default_factory=tuple
    )

    @property
    def version_name(self) -> str | None:
        """项目内部接口说明。"""
        return self.version.name if self.version else None

    @property
    def payload(self) -> Any:
        """项目内部接口说明。"""
        return self.version.payload if self.version else None
