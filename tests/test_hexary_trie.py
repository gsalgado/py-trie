import pytest

import itertools
import fnmatch
import json
import os

from eth_utils import (
    is_0x_prefixed,
    decode_hex,
    force_bytes,
)

from trie.hexary import (
    HexaryTrie,
)


def normalize_fixture(fixture):
    normalized_fixture = {
        'in': tuple(
            (
                decode_hex(key) if is_0x_prefixed(key) else force_bytes(key),
                (
                    decode_hex(value) if is_0x_prefixed(value) else force_bytes(value)
                ) if value is not None else None,
            )
            for key, value
            in (fixture['in'].items() if isinstance(fixture['in'], dict) else fixture['in'])
        ),
        'root': decode_hex(fixture['root'])
    }
    return normalized_fixture


ROOT_PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))


def recursive_find_files(base_dir, pattern):
    for dirpath, _, filenames in os.walk(base_dir):
        for filename in filenames:
            if fnmatch.fnmatch(filename, pattern):
                yield os.path.join(dirpath, filename)


BASE_FIXTURE_PATH = os.path.join(ROOT_PROJECT_DIR, 'fixtures', 'TrieTests')


FIXTURES_PATHS = tuple(recursive_find_files(BASE_FIXTURE_PATH, "trietest.json"))
NEXT_PREV_FIXTURE_PATH = os.path.join(BASE_FIXTURE_PATH, "trietestnextprev.json")


def test_fixtures_exist():
    assert os.path.exists(BASE_FIXTURE_PATH)
    assert FIXTURES_PATHS


RAW_FIXTURES = tuple(
    (
        os.path.basename(fixture_path),
        json.load(open(fixture_path)),
    ) for fixture_path in FIXTURES_PATHS
)
RAW_NEXT_PREV_FIXTURES = [
    (os.path.basename(NEXT_PREV_FIXTURE_PATH), json.load(open(NEXT_PREV_FIXTURE_PATH)))
]


FIXTURES = tuple(
    (
        "{0}:{1}".format(fixture_filename, key),
        normalize_fixture(fixtures[key]),
    )
    for fixture_filename, fixtures in RAW_FIXTURES
    for key in sorted(fixtures.keys())
)
NEXT_PREV_FIXTURES = [
    ("{0}:{1}".format(fixture_filename, key), fixtures[key])
    for fixture_filename, fixtures in RAW_NEXT_PREV_FIXTURES
    for key in sorted(fixtures.keys())
]


@pytest.mark.parametrize(
    'fixture_name,fixture', FIXTURES,
)
def test_trie_using_fixtures(fixture_name, fixture):

    keys_and_values = fixture['in']
    deletes = tuple(k for k, v in keys_and_values if v is None)
    remaining = {
        k: v
        for k, v
        in keys_and_values
        if k not in deletes
    }

    for kv_permutation in itertools.islice(itertools.permutations(keys_and_values), 100):
        print("in it")
        trie = HexaryTrie(db={})

        for key, value in kv_permutation:
            if value is None:
                del trie[key]
            else:
                trie[key] = value
        for key in deletes:
            del trie[key]

        for key, expected_value in remaining.items():
            assert key in trie
            actual_value = trie[key]
            assert actual_value == expected_value

        for key in deletes:
            assert key not in trie

        expected_root = fixture['root']
        actual_root = trie.root_hash

        assert actual_root == expected_root


@pytest.mark.parametrize(
    'fixture_name,fixture', NEXT_PREV_FIXTURES,
)
def test_trie_next_prev_using_fixtures(fixture_name, fixture):
    trie = HexaryTrie(db={})
    for k in fixture['in']:
        k = force_bytes(k)
        trie[k] = k

    nxt = trie.next(b'')
    assert nxt is not None
    while nxt is not None:
        print(nxt)
        nxt = trie.next(nxt)

    for point, prev, nxt in fixture['tests']:
        point = force_bytes(point)
        prev = force_bytes(prev)
        nxt = force_bytes(nxt)
        assert nxt == (trie.next(point) or b'')
        assert prev == (trie.prev(point) or b'')
