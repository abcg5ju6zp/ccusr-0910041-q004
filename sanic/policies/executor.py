"""把策略版本选择接入请求生命周期。

一次请求在进入 ``handle_request`` 时通过 :meth:`PolicyManager.select`
完成**唯一一次**版本选择，结果缓存在请求上下文上且不可变；请求钩子、
异常钩子、响应钩子和结束钩子都从缓存读取同一批 :class:`PolicySelection`，
因此灰度比例调整或 :meth:`PolicyRegistry.rollback` 不会改变在途请求
使用的版本。
"""

from __future__ import annotations

import time

from inspect import isawaitable
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Iterable,
)

from sanic.log import error_logger, logger
from sanic.policies.core import (
    POLICY_VERSION_HEADER,
    PolicyRegistry,
    PolicySelection,
    sanitize_tenant,
)
from sanic.response import BaseHTTPResponse, ResponseStream


if TYPE_CHECKING:
    from sanic.app import Sanic
    from sanic.request import Request

#: 请求上下文上存放状态的属性名
STATE_ATTR = "_policy_state"

#: 默认租户头与稳定分桶身份头（注册表本身不解析凭据类头）
DEFAULT_TENANT_HEADER = "x-tenant-id"
DEFAULT_IDENTITY_HEADER = "x-rollout-key"
DEFAULT_PIN_HEADER = "x-policy-pin"

TenantResolver = Callable[["Request"], str | None]
IdentityResolver = Callable[["Request"], str | None]
PinnedResolver = Callable[["Request"], str | None]
ExemptionResolver = Callable[["Request"], bool]
AuditSink = Callable[..., Any]


class _RequestPolicyState:
    """单个请求的策略执行状态。选择结果一经写入不再变化。"""

    __slots__ = (
        "selections",
        "request_ran",
        "exception_ran",
        "response_ran",
        "complete_ran",
        "started_at",
    )

    def __init__(self, selections: dict[str, PolicySelection]) -> None:
        self.selections = selections
        self.request_ran: set[str] = set()
        self.exception_ran: set[str] = set()
        self.response_ran: set[str] = set()
        self.complete_ran: set[str] = set()
        self.started_at = time.monotonic()


def default_audit_sink(request: "Request", event: dict[str, Any]) -> None:
    """可直接启用的审计出口：写入 ``sanic.policies.audit`` 日志。

    事件内容由 :meth:`PolicySelection.audit` 生成，不含请求凭据。
    """

    logger.info("policy.audit %s", event)


def _state(request: "Request") -> _RequestPolicyState | None:
    ctx = getattr(request, "_ctx", None)
    return getattr(ctx, STATE_ATTR, None) if ctx is not None else None


def _get_or_create_state(
    request: "Request", selections: dict[str, PolicySelection]
) -> _RequestPolicyState:
    ctx = request.ctx
    existing = getattr(ctx, STATE_ATTR, None)
    if existing is None:
        existing = _RequestPolicyState(selections)
        setattr(ctx, STATE_ATTR, existing)
    return existing


class PolicyManager:
    """持有全部策略注册表，并负责在请求各阶段执行选定版本的钩子。

    通过 ``app.policy_manager`` 访问。常规配置方式::

        manager = app.policy_manager
        manager.tenant_resolver = lambda request: request.headers.get(...)
        manager.audit_sink = default_audit_sink
        manager.add(registry)
    """

    def __init__(self, app: "Sanic") -> None:
        self.app = app
        self._registries: dict[str, PolicyRegistry] = {}
        self._order: list[str] = []
        # 强引用在途的异步审计任务，防止事件循环在完成前回收
        self._audit_tasks: set[Awaitable[Any]] = set()

        # 可替换的解析器；默认实现只读取非凭据类请求头/连接信息
        self.tenant_resolver: TenantResolver | None = self._default_tenant
        self.identity_resolver: IdentityResolver = self._default_identity
        self.pinned_resolver: PinnedResolver | None = None
        self.exemption_resolver: ExemptionResolver | None = None

        #: 审计出口；为 None 时不落任何审计记录
        self.audit_sink: AuditSink | None = None
        #: 是否在响应头回写实际使用的版本，便于响应阶段确认
        self.announce_response_header = True
        #: 是否允许从默认钉版头读取版本（默认关闭：钉版需由受信逻辑决定）
        self.allow_pinned_header = False

    # ------------------------------------------------------------------ #
    # 配置
    # ------------------------------------------------------------------ #

    def add(self, registry: PolicyRegistry) -> PolicyRegistry:
        if registry.name in self._registries:
            raise ValueError(f"策略注册表 {registry.name!r} 已存在")
        self._registries[registry.name] = registry
        self._order.append(registry.name)
        return registry

    def get(self, name: str) -> PolicyRegistry:
        return self._registries[name]

    def registries(self) -> Iterable[PolicyRegistry]:
        return tuple(self._registries.values())

    def exempt_paths(self, *patterns: str) -> None:
        """便捷方法：按正则路径豁免所有注册表（命中时仍使用默认版本）。"""

        import re

        compiled = tuple(re.compile(p) for p in patterns)

        def resolver(request: "Request") -> bool:
            return any(p.search(request.path) for p in compiled)

        previous = self.exemption_resolver
        if previous is None:
            self.exemption_resolver = resolver
        else:
            self.exemption_resolver = lambda r: previous(r) or resolver(r)  # noqa: E731

    # ------------------------------------------------------------------ #
    # 选择（每请求恰好一次）
    # ------------------------------------------------------------------ #

    def select(self, request: "Request") -> dict[str, PolicySelection]:
        """返回本请求的版本选择；重复调用返回同一份不可变结果。"""

        state = _state(request)
        if state is not None:
            return state.selections

        tenant = self._resolve_tenant(request)
        identity = self._safe_call(
            self.identity_resolver, request, label="identity"
        )
        pinned = self._resolve_pinned(request)
        exempt = bool(
            self._safe_call(self.exemption_resolver, request, label="exempt")
        )

        selections: dict[str, PolicySelection] = {}
        for name in self._order:
            registry = self._registries[name]
            selections[name] = registry.select(
                request,
                tenant=tenant,
                identity=identity,
                pinned_version=pinned,
                exempt=exempt,
            )

        state = _get_or_create_state(request, selections)
        for selection in state.selections.values():
            self._audit(request, "selected", selection)
        return state.selections

    def selection_for(
        self, request: "Request", registry_name: str
    ) -> PolicySelection | None:
        state = _state(request)
        if state is None:
            return None
        return state.selections.get(registry_name)

    # ------------------------------------------------------------------ #
    # 各阶段执行
    # ------------------------------------------------------------------ #

    async def run_request(
        self, request: "Request"
    ) -> BaseHTTPResponse | ResponseStream | None:
        """请求阶段：执行所有注册表选定版本的 ``on_request`` 钩子。

        任一钩子返回响应即短路（按注册表优先级顺序），异常向上抛出，
        交由 ``handle_exception`` 使用**同一版本**处理。返回值语义与
        Sanic 请求中间件一致（``HTTPResponse`` 或 ``ResponseStream``）。
        """

        selections = self.select(request)
        state = _state(request)
        assert state is not None
        response: BaseHTTPResponse | ResponseStream | None = None
        for name, selection in selections.items():
            if name in state.request_ran:
                continue
            state.request_ran.add(name)
            version = selection.version
            if version is None or version.on_request is None:
                continue
            result = await self._invoke(version.on_request, request)
            if isinstance(result, (BaseHTTPResponse, ResponseStream)):
                response = result
                break
        return response

    async def run_exception(
        self, request: "Request", exception: BaseException
    ) -> BaseHTTPResponse | None:
        """异常阶段：观测或替换错误响应。每个注册表只执行一次。

        钩子自身的异常被记录并吞掉，避免异常处理无限递归。
        """

        selections = self.select(request)
        state = _state(request)
        assert state is not None
        for name, selection in selections.items():
            if name in state.exception_ran:
                continue
            state.exception_ran.add(name)
            version = selection.version
            if version is None or version.on_exception is None:
                continue
            try:
                result = await self._invoke(
                    version.on_exception, request, exception
                )
            except Exception as e:  # noqa: BLE001
                error_logger.exception(
                    "Policy exception hook %r failed: %s", version.name, e
                )
                continue
            if isinstance(result, BaseHTTPResponse):
                return result
        return None

    async def run_response(
        self,
        request: "Request",
        response: BaseHTTPResponse,
    ) -> BaseHTTPResponse:
        """响应阶段：执行 ``on_response`` 钩子并回写版本确认头。

        确认头在所有钩子执行后写到**最终**响应对象上，保证客户端看到的
        版本与实际执行版本一致。
        """

        selections = self.select(request)
        state = _state(request)
        assert state is not None

        for name, selection in selections.items():
            if name in state.response_ran:
                continue
            state.response_ran.add(name)
            version = selection.version
            if version is None or version.on_response is None:
                continue
            try:
                result = await self._invoke(
                    version.on_response, request, response
                )
            except Exception as e:  # noqa: BLE001
                error_logger.exception(
                    "Policy response hook %r failed: %s", version.name, e
                )
                continue
            if isinstance(result, BaseHTTPResponse):
                if request.stream:
                    response = request.stream.respond(result)
                    if isawaitable(response):
                        response = await response
                else:
                    response = result

        if self.announce_response_header and hasattr(response, "headers"):
            announced = ",".join(
                f"{name}={selection.version_name}"
                for name, selection in selections.items()
                if selection.version_name is not None
            )
            if announced:
                response.headers.setdefault(POLICY_VERSION_HEADER, announced)
        return response

    async def complete(
        self,
        request: "Request",
        exception: BaseException | None = None,
    ) -> None:
        """响应结束阶段：只做观测。任何失败都不影响已结束的响应。"""

        state = _state(request)
        if state is None:
            return
        for name in tuple(state.selections):
            if name in state.complete_ran:
                continue
            state.complete_ran.add(name)
            selection = state.selections[name]
            version = selection.version
            self._audit(
                request,
                "completed",
                selection,
                error=type(exception).__name__ if exception else None,
                duration_ms=round(
                    (time.monotonic() - state.started_at) * 1000, 2
                ),
            )
            if version is None or version.on_complete is None:
                continue
            try:
                await self._invoke(
                    version.on_complete, request, exception=exception
                )
            except Exception as e:  # noqa: BLE001
                error_logger.exception(
                    "Policy complete hook %r failed: %s", version.name, e
                )

    # ------------------------------------------------------------------ #
    # 默认解析器与审计
    # ------------------------------------------------------------------ #

    def _default_tenant(self, request: "Request") -> str | None:
        return sanitize_tenant(request.headers.get(DEFAULT_TENANT_HEADER))

    def _default_identity(self, request: "Request") -> str | None:
        pinned = request.headers.get(DEFAULT_IDENTITY_HEADER)
        if pinned:
            return pinned
        try:
            ip = request.ip
        except Exception:  # noqa: BLE001
            return None
        return ip or None

    def _resolve_pinned(self, request: "Request") -> str | None:
        if self.pinned_resolver is not None:
            value = self._safe_call(
                self.pinned_resolver, request, label="pinned"
            )
            return value or None
        if self.allow_pinned_header:
            return request.headers.get(DEFAULT_PIN_HEADER) or None
        return None

    def _resolve_tenant(self, request: "Request") -> str | None:
        if self.tenant_resolver is None:
            return None
        return self._safe_call(self.tenant_resolver, request, label="tenant")

    def _safe_call(
        self,
        resolver: Callable[..., Any] | None,
        request,
        *,
        label: str,
    ) -> Any:
        if resolver is None:
            return None
        try:
            return resolver(request)
        except Exception as e:  # noqa: BLE001
            error_logger.exception("Policy %s resolver failed: %s", label, e)
            return None

    def _audit(
        self,
        request: "Request",
        stage: str,
        selection: PolicySelection,
        **extra: Any,
    ) -> None:
        sink = self.audit_sink
        if sink is None:
            return
        # 只放入白名单字段：request_id 是服务端生成的标识，不是凭据
        event: dict[str, Any] = {"stage": stage}
        try:
            event["request_id"] = str(request.id)
        except Exception:  # noqa: BLE001
            event["request_id"] = None
        try:
            event["method"] = request.method
            event["path_template"] = request.uri_template
        except Exception:  # noqa: BLE001
            pass
        event.update(selection.audit())
        event.update({k: v for k, v in extra.items() if v is not None})
        try:
            result = sink(request, event)
            if isawaitable(result):
                # 审计落盘不阻塞响应生命周期；保留强引用并在完成时移除
                future = request.app.loop.create_task(result)
                self._audit_tasks.add(future)
                future.add_done_callback(self._discard_audit_task)
        except Exception as e:  # noqa: BLE001
            error_logger.exception("Policy audit sink failed: %s", e)

    def _discard_audit_task(self, future: Awaitable[Any]) -> None:
        self._audit_tasks.discard(future)
        _log_task_error(future)

    @staticmethod
    async def _invoke(
        hook: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        result = hook(*args, **kwargs)
        if isawaitable(result):
            result = await result
        return result


def _log_task_error(future: Awaitable[Any]) -> None:
    try:
        future.result()  # type: ignore[attr-defined]
    except Exception as e:  # noqa: BLE001
        error_logger.exception("Async policy audit sink failed: %s", e)
