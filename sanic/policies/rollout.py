from __future__ import annotations

import threading


#: 稳定分桶空间：bucket = 0 .. (BUCKET_SPACE - 1)
BUCKET_SPACE = 10_000


class Rollout:
    """灰度比例配置。

    :param percentage: 0.0 ~ 100.0，稳定分桶小于阈值的请求进入灰度
    :param key: 可选的固定分桶身份（用于内部定向验证）；设置后只允许
        该身份命中，比例仍需 > 0
    """

    __slots__ = ("_lock", "_percentage", "key")

    def __init__(
        self,
        percentage: float = 100.0,
        *,
        key: str | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self.key = key
        self.percentage = percentage

    def __repr__(self) -> str:
        return f"Rollout(percentage={self._percentage}, key={self.key!r})"

    @property
    def percentage(self) -> float:
        return self._percentage

    @percentage.setter
    def percentage(self, value: float) -> None:
        percentage = float(value)
        if not 0.0 <= percentage <= 100.0:
            raise ValueError("灰度比例必须在 0.0 ~ 100.0 之间")
        with self._lock:
            self._percentage = percentage

    @property
    def cutoff(self) -> int:
        """分桶截止值（不含）：``bucket < cutoff`` 即命中。"""

        with self._lock:
            return int(self._percentage * BUCKET_SPACE / 100)

    def includes(self, bucket: int) -> bool:
        return 0 <= bucket < self.cutoff

    def update(self, percentage: float, *, key: str | None = None) -> None:
        """运行期调整比例/定向身份；在途请求的选择结果不受影响。"""

        with self._lock:
            self.key = key
            self.percentage = percentage
