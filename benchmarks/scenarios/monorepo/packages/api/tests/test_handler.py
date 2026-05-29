from packages.api.src.handler import add_item


def test_add_item():
    assert add_item({}, "a", 1) == {"a": 1}
