from __future__ import annotations

from typing import TYPE_CHECKING

from sanic.log import error_logger
from sanic.strategies.manager import PolicyRegistry


if TYPE_CHECKING:
    from sanic.app import Sanic
    from sanic.request.types import Request
    from sanic.response.types import BaseHTTPResponse

#: 版本化执行逻辑放在中间件洋葱模型的最内层（紧邻处理器），
#: 不改变任何现有蓝图/应用级中间件的相对顺序。
_POLICY_MIDDLEWARE_PRIORITY = -1_000_000

#: 版本选择必须早于任何业务信号与中间件完成，使用最高信号优先级。
_POLICY_SIGNAL_PRIORITY = 1_000_000


def install_policy_support(app: "Sanic", registry: PolicyRegistry) -> None:
    """把策略选择与执行惰性接入应用的请求生命周期。

    只在用户首次注册策略时安装一次；未使用策略的应用中间件链与之前
    完全一致。

    - ``http.lifecycle.request`` 信号（最早入口，HTTP/1 与 ASGI 共用）：
      一次性冻结全部策略决策，异常处理与响应阶段不会重新选择；
    - 应用级请求中间件（最低优先级，洋葱模型最内层）：执行选中版本的
      请求钩子，且在异常处理重放中间件时不会重复执行；
    - 应用级响应中间件（最低优先级，响应阶段最先执行）：执行选中版本的
      响应钩子（逆序，与现有请求/响应中间件洋葱模型一致）；
    - ``http.lifecycle.response`` 信号（响应发送前最后一刻）：在最终
      响应上标记版本；即使响应中间件替换过响应、或请求走了异常处理，
      调用方也能确认实际版本。
    """

    async def _resolve_policy(request: "Request") -> None:
        try:
            await registry.resolve(request)
        except Exception:  # noqa: BLE001
            error_logger.exception(
                "Failed to resolve request policy; continuing without a "
                "policy version"
            )

    async def _policy_request_middleware(request: "Request"):
        if request._policy_decisions is None:
            return None
        # 异常处理可能重放整条请求中间件链；同一请求只执行一次版本钩子，
        # 始终使用进入时冻结的版本。
        if request._policy_request_hooks_done:
            return None
        request._policy_request_hooks_done = True
        return await registry.run_request_hooks(request)

    async def _policy_response_middleware(
        request: "Request", response: "BaseHTTPResponse"
    ):
        if request._policy_decisions is None:
            return None
        result = await registry.run_response_hooks(request, response)
        return result if result is not response else None

    async def _mark_policy_response(
        request: "Request", response: "BaseHTTPResponse"
    ) -> None:
        if request._policy_decisions is None or response is None:
            return
        registry.mark_response(request, response)

    app.signal(
        "http.lifecycle.request",
        priority=_POLICY_SIGNAL_PRIORITY,
    )(_resolve_policy)
    app.register_middleware(
        _policy_request_middleware,
        "request",
        priority=_POLICY_MIDDLEWARE_PRIORITY,
    )
    app.register_middleware(
        _policy_response_middleware,
        "response",
        priority=_POLICY_MIDDLEWARE_PRIORITY,
    )
    app.signal(
        "http.lifecycle.response",
        priority=_POLICY_SIGNAL_PRIORITY,
    )(_mark_policy_response)
