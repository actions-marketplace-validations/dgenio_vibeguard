"""Rule package for VibeGuard."""


def load_all_builtin_rules() -> None:
    """Import every built-in rule module so ``RULE_REGISTRY`` is populated.

    Call this from code that needs the registry populated without importing
    the scanner (which has its own top-level imports). Idempotent — repeated
    calls are harmless since Python caches module imports.
    """
    import vibeguard.rules.agent_memory  # noqa: F401
    import vibeguard.rules.ai_footprints  # noqa: F401
    import vibeguard.rules.auth  # noqa: F401
    import vibeguard.rules.ci_docker  # noqa: F401
    import vibeguard.rules.dependencies  # noqa: F401
    import vibeguard.rules.go_rules  # noqa: F401
    import vibeguard.rules.iac  # noqa: F401
    import vibeguard.rules.packaging  # noqa: F401
    import vibeguard.rules.risky_diff  # noqa: F401
    import vibeguard.rules.secrets  # noqa: F401
    import vibeguard.rules.sourcemaps  # noqa: F401
    import vibeguard.rules.sql  # noqa: F401
    import vibeguard.rules.tests  # noqa: F401
