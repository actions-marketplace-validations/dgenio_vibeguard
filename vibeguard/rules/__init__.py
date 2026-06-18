"""Rule package for VibeGuard."""


def load_all_builtin_rules() -> None:
    """Import every built-in rule module so ``RULE_REGISTRY`` is populated.

    Call this from code that needs the registry populated without importing the
    scanner. Importing :mod:`vibeguard.rules.builtin` pulls in every built-in
    rule module — which runs each rule's ``register_rule`` side effect — so this
    is the single place the built-in rule set is enumerated (#175). Idempotent:
    repeated calls are harmless since Python caches module imports.
    """
    import vibeguard.rules.builtin  # noqa: F401
