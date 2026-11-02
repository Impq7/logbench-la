"""ASB 四策略 → AgentDojo 官方扩展点接入。

导入本包即把 asb_concat / asb_escape / asb_context_ignore / asb_fake_completion
四个攻击注册进官方 `agentdojo.attacks.attack_registry.ATTACKS`，供官方 CLI 的
`--module-to-load logbench.agentdojo_asb` + `--attack asb_*` 使用。
"""

from logbench.agentdojo_asb.attacks import (  # noqa: F401
    ASBConcat,
    ASBContextIgnore,
    ASBEscape,
    ASBFakeCompletion,
)

__all__ = ["ASBConcat", "ASBEscape", "ASBContextIgnore", "ASBFakeCompletion"]
