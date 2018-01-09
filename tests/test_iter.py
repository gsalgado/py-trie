from trie import HexaryTrie

from hypothesis import (
    given,
    settings,
    strategies,
)


def make_random_trie(random):
    trie = HexaryTrie({})
    contents = {}
    for _ in range(1000):
        key_length = random.randint(2, 32)
        key = bytes([random.randint(0,255) for _ in range(key_length)])
        value_length = random.randint(2, 64)
        value = bytes([random.randint(0, 255) for _ in range(value_length)])
        trie[key] = value
        contents[key] = value
    return trie, contents


@given(random=strategies.randoms())
@settings(max_examples=10)
def test_iter(random):
    trie, contents = make_random_trie(random)
    visited = []
    key = trie.next(b'')
    assert key is not None
    while key is not None:
        visited.append(key)
        key = trie.next(key)

    assert visited == sorted(contents.keys())

    last_key = visited[-1]
    visited = [last_key]
    key = trie.prev(last_key)
    while key is not None:
        visited.append(key)
        key = trie.prev(key)

    assert visited == sorted(contents.keys(), reverse=True)
