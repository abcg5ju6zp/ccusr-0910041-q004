# Sanic 服务框架

本项目提供异步 HTTP 服务、路由、蓝图、中间件、信号和工作进程管理能力。生产源码位于 `sanic/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install -e . pytest sanic-testing pytest-asyncio`

## 测试

`python3 -m pytest -q tests/test_blueprints.py tests/test_blueprint_group.py`

## 构建

`python3 -m compileall -q sanic`

## 使用

应用通过 `Sanic` 创建服务，通过蓝图组合路由，并可使用测试客户端完成本地 HTTP 验收。

## 可版本化的请求策略

`sanic.policies` 提供可灰度、可回退的版本化策略机制。与全局中间件不同，
**每个请求在进入时只做一次版本选择**，请求中间件、处理器、异常处理、
响应中间件和响应结束阶段始终使用同一个版本；运行期调整灰度比例或立即回退
不会影响在途请求。

```python
from sanic import Sanic, json
from sanic.policies import PolicyRegistry, PolicyVersion, Rollout

app = Sanic("example")
security = PolicyRegistry("security")

security.add(PolicyVersion(name="v1"), make_default=True)
security.add(
    PolicyVersion(
        name="v2",
        priority=10,
        rollout=Rollout(25.0),          # 稳定分桶 25% 灰度
        on_request=lambda request: None,
        on_exception=lambda request, exception: None,
        on_response=lambda request, response: response,
        on_complete=lambda request, exception=None: None,
    ),
    tenants={"acme"},                    # 仅对该租户灰度
)
security.exempt("v1", tenants=["acme-internal"])  # 显式豁免
app.policy_manager.add(security)
```

- **优先级**：同一租户命中多个版本时，按 `priority` 降序，注册顺序决胜。
- **灰度比例**：`security.canary("v2", 50.0)` 运行期立即调整；分桶键取
  `x-rollout-key` 请求头，缺省时退化为客户端 IP / 租户整桶，同一身份结果稳定。
- **钉版**：设置 `policy_manager.pinned_resolver`（如解析受信内部头）显式指定版本。
- **豁免**：`exempt(...)` 或 `policy_manager.exempt_paths(r"^/healthz")`。
- **回退**：`security.rollback("v1")` 立即把全部非豁免灰度比例置零并切回默认版本。
- **版本确认**：响应头 `x-policy-version: security=v2` 标明实际生效的版本。
- **审计**：设置 `policy_manager.audit_sink` 后，每个请求记录
  `selected` 与 `completed` 事件，包含版本、原因（`exempt` / `pinned` /
  `canary_included` / `canary_excluded` / `default`）、租户、桶位与耗时；
  事件白名单不含 URL 查询串、`Authorization`、`Cookie`、API Key 等凭据。

完整行为见 `tests/test_policy_rollout.py`。

