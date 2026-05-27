"""True-positive / false-positive corpus for rule precision measurement (#53).

Directory layout::

    corpus/
      <rule_category>/
        tp_*.<ext>   # should trigger at least one finding for the rule
        fp_*.<ext>   # benign-looking; must not trigger CRITICAL/HIGH for the rule

The driver ``tests/test_corpus_precision.py`` discovers and validates the
entire tree. Add a new category by dropping in a directory; add a new
case by dropping in a ``tp_`` or ``fp_`` file matching the naming convention.
"""
