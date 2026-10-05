from __future__ import annotations

from enum import Enum


class SelectionReason(str, Enum):
    """解释一次策略版本选择的原因。

    取值会原样写入审计记录，因此只描述"为什么选"，
    不携带任何请求内容（头、查询参数、Cookie 等）。
    """

    #: 显式命中豁免规则，使用被豁免的版本
    EXEMPT = "exempt"
    #: 请求通过显式钉版（如内部调试头）指定了版本
    PINNED = "pinned"
    #: 命中灰度规则，且稳定分桶落在灰度比例之内
    CANARY_INCLUDED = "canary_included"
    #: 命中灰度规则，但稳定分桶落在灰度比例之外
    CANARY_EXCLUDED = "canary_excluded"
    #: 没有任何规则命中，使用注册表当前的默认版本
    DEFAULT = "default"
    #: 请求的注册表上还没有注册任何版本
    UNCONFIGURED = "unconfigured"
