import itertools

import rlp

from trie.constants import (
    BLANK_NODE,
    BLANK_NODE_HASH,
    NODE_TYPE_BLANK,
    NODE_TYPE_LEAF,
    NODE_TYPE_EXTENSION,
    NODE_TYPE_BRANCH,
    BLANK_HASH,
)
from trie.exceptions import BadTrieProof
from trie.validation import (
    validate_is_node,
    validate_is_bytes,
)
from trie.utils.sha3 import (
    keccak,
)
from trie.utils.nibbles import (
    bytes_to_nibbles,
    decode_nibbles,
    encode_nibbles,
    nibbles_to_bytes,
    remove_nibbles_terminator,
)
from trie.utils.nodes import (
    get_node_type,
    extract_key,
    compute_leaf_key,
    compute_extension_key,
    is_extension_node,
    is_leaf_node,
    is_blank_node,
    consume_common_prefix,
    key_starts_with,
)


# sanity check
assert BLANK_NODE_HASH == keccak(rlp.encode(b''))
assert BLANK_HASH == keccak(b'')


class HexaryTrie(object):
    db = None
    root_hash = None

    # Shortcuts
    BLANK_NODE_HASH = BLANK_NODE_HASH
    BLANK_NODE = BLANK_NODE

    def __init__(self, db, root_hash=BLANK_NODE_HASH):
        self.db = db
        validate_is_bytes(root_hash)
        self.root_hash = root_hash

    def get(self, key):
        validate_is_bytes(key)

        trie_key = bytes_to_nibbles(key)
        root_node = self._get_node(self.root_hash)

        return self._get(root_node, trie_key)

    def _get(self, node, trie_key):
        node_type = get_node_type(node)

        if node_type == NODE_TYPE_BLANK:
            return BLANK_NODE
        elif node_type in {NODE_TYPE_LEAF, NODE_TYPE_EXTENSION}:
            return self._get_kv_node(node, trie_key)
        elif node_type == NODE_TYPE_BRANCH:
            return self._get_branch_node(node, trie_key)
        else:
            raise Exception("Invariant: This shouldn't ever happen")

    def set(self, key, value):
        validate_is_bytes(key)
        validate_is_bytes(value)

        trie_key = bytes_to_nibbles(key)
        root_node = self._get_node(self.root_hash)

        new_node = self._set(root_node, trie_key, value)
        self._set_root_node(new_node)

    def _set(self, node, trie_key, value):
        node_type = get_node_type(node)

        if node_type == NODE_TYPE_BLANK:
            return [
                compute_leaf_key(trie_key),
                value,
            ]
        elif node_type in {NODE_TYPE_LEAF, NODE_TYPE_EXTENSION}:
            return self._set_kv_node(node, trie_key, value)
        elif node_type == NODE_TYPE_BRANCH:
            return self._set_branch_node(node, trie_key, value)
        else:
            raise Exception("Invariant: This shouldn't ever happen")

    def exists(self, key):
        validate_is_bytes(key)

        return self.get(key) != BLANK_NODE

    def delete(self, key):
        validate_is_bytes(key)

        trie_key = bytes_to_nibbles(key)
        root_node = self._get_node(self.root_hash)

        new_node = self._delete(root_node, trie_key)
        self._set_root_node(new_node)

    def _delete(self, node, trie_key):
        node_type = get_node_type(node)

        if node_type == NODE_TYPE_BLANK:
            return BLANK_NODE
        elif node_type in {NODE_TYPE_LEAF, NODE_TYPE_EXTENSION}:
            return self._delete_kv_node(node, trie_key)
        elif node_type == NODE_TYPE_BRANCH:
            return self._delete_branch_node(node, trie_key)
        else:
            raise Exception("Invariant: This shouldn't ever happen")

    #
    # Trie Proofs
    #
    @classmethod
    def get_from_proof(cls, root_hash, key, proof):
        trie = cls({})

        for node in proof:
            trie._persist_node(node)
        trie.root_hash = root_hash
        try:
            return trie.get(key)
        except KeyError as e:
            raise BadTrieProof("Missing proof node with hash {}".format(e.args))

    #
    # Convenience
    #
    @property
    def root_node(self):
        return self._get_node(self.root_hash)

    @root_node.setter
    def root_node(self, value):
        self._set_root_node(value)

    #
    # Utils
    #
    def _set_root_node(self, root_node):
        validate_is_node(root_node)
        encoded_root_node = rlp.encode(root_node)
        self.root_hash = keccak(encoded_root_node)
        self.db[self.root_hash] = encoded_root_node

    def _get_node(self, node_hash):
        if node_hash == BLANK_NODE:
            return BLANK_NODE
        elif node_hash == BLANK_NODE_HASH:
            return BLANK_NODE

        if len(node_hash) < 32:
            encoded_node = node_hash
        else:
            encoded_node = self.db[node_hash]
        node = self._decode_node(encoded_node)

        return node

    def _persist_node(self, node):
        validate_is_node(node)
        if is_blank_node(node):
            return BLANK_NODE
        encoded_node = rlp.encode(node)
        if len(encoded_node) < 32:
            return node

        encoded_node_hash = keccak(encoded_node)
        self.db[encoded_node_hash] = encoded_node
        return encoded_node_hash

    def _decode_node(self, encoded_node_or_hash):
        if encoded_node_or_hash == BLANK_NODE:
            return BLANK_NODE
        elif isinstance(encoded_node_or_hash, list):
            return encoded_node_or_hash
        else:
            return rlp.decode(encoded_node_or_hash)

    #
    # Node Operation Helpers
    def _normalize_branch_node(self, node):
        """
        A branch node which is left with only a single non-blank item should be
        turned into either a leaf or extension node.
        """
        iter_node = iter(node)
        if any(iter_node) and any(iter_node):
            return node

        if node[16]:
            return [compute_leaf_key([]), node[16]]

        sub_node_idx, sub_node_hash = next(
            (idx, v)
            for idx, v
            in enumerate(node[:16])
            if v
        )
        sub_node = self._get_node(sub_node_hash)
        sub_node_type = get_node_type(sub_node)

        if sub_node_type in {NODE_TYPE_LEAF, NODE_TYPE_EXTENSION}:
            new_subnode_key = encode_nibbles(tuple(itertools.chain(
                [sub_node_idx],
                decode_nibbles(sub_node[0]),
            )))
            return [new_subnode_key, sub_node[1]]
        elif sub_node_type == NODE_TYPE_BRANCH:
            subnode_hash = self._persist_node(sub_node)
            return [encode_nibbles([sub_node_idx]), subnode_hash]
        else:
            raise Exception("Invariant: this code block should be unreachable")

    #
    # Node Operations
    #
    def _delete_branch_node(self, node, trie_key):
        if not trie_key:
            node[-1] = BLANK_NODE
            return self._normalize_branch_node(node)

        node_to_delete = self._get_node(node[trie_key[0]])

        sub_node = self._delete(node_to_delete, trie_key[1:])
        encoded_sub_node = self._persist_node(sub_node)

        if encoded_sub_node == node[trie_key[0]]:
            return node

        node[trie_key[0]] = encoded_sub_node
        if encoded_sub_node == BLANK_NODE:
            return self._normalize_branch_node(node)

        return node

    def _delete_kv_node(self, node, trie_key):
        current_key = extract_key(node)

        if not key_starts_with(trie_key, current_key):
            # key not present?....
            return node

        node_type = get_node_type(node)

        if node_type == NODE_TYPE_LEAF:
            if trie_key == current_key:
                return BLANK_NODE
            else:
                return node

        sub_node_key = trie_key[len(current_key):]
        sub_node = self._get_node(node[1])

        new_sub_node = self._delete(sub_node, sub_node_key)
        encoded_new_sub_node = self._persist_node(new_sub_node)

        if encoded_new_sub_node == node[1]:
            return node

        if new_sub_node == BLANK_NODE:
            return BLANK_NODE

        new_sub_node_type = get_node_type(new_sub_node)
        if new_sub_node_type in {NODE_TYPE_LEAF, NODE_TYPE_EXTENSION}:
            new_key = current_key + decode_nibbles(new_sub_node[0])
            return [encode_nibbles(new_key), new_sub_node[1]]

        if new_sub_node_type == NODE_TYPE_BRANCH:
            return [encode_nibbles(current_key), encoded_new_sub_node]

        raise Exception("Invariant, this code path should not be reachable")

    def _set_branch_node(self, node, trie_key, value):
        if trie_key:
            sub_node = self._get_node(node[trie_key[0]])

            new_node = self._set(sub_node, trie_key[1:], value)
            node[trie_key[0]] = self._persist_node(new_node)
        else:
            node[-1] = value
        return node

    def _set_kv_node(self, node, trie_key, value):
        current_key = extract_key(node)
        common_prefix, current_key_remainder, trie_key_remainder = consume_common_prefix(
            current_key,
            trie_key,
        )
        is_extension = is_extension_node(node)

        if not current_key_remainder and not trie_key_remainder:
            if is_leaf_node(node):
                return [node[0], value]
            else:
                sub_node = self._get_node(node[1])
                # TODO: this needs to cleanup old storage.
                new_node = self._set(sub_node, trie_key_remainder, value)
        elif not current_key_remainder:
            if is_extension:
                sub_node = self._get_node(node[1])
                # TODO: this needs to cleanup old storage.
                new_node = self._set(sub_node, trie_key_remainder, value)
            else:
                subnode_position = trie_key_remainder[0]
                subnode_key = compute_leaf_key(trie_key_remainder[1:])
                sub_node = [subnode_key, value]

                new_node = [BLANK_NODE] * 16 + [node[1]]
                new_node[subnode_position] = self._persist_node(sub_node)
        else:
            new_node = [BLANK_NODE] * 17

            if len(current_key_remainder) == 1 and is_extension:
                new_node[current_key_remainder[0]] = node[1]
            else:
                if is_extension:
                    compute_key_fn = compute_extension_key
                else:
                    compute_key_fn = compute_leaf_key

                new_node[current_key_remainder[0]] = self._persist_node([
                    compute_key_fn(current_key_remainder[1:]),
                    node[1],
                ])

            if trie_key_remainder:
                new_node[trie_key_remainder[0]] = self._persist_node([
                    compute_leaf_key(trie_key_remainder[1:]),
                    value,
                ])
            else:
                new_node[-1] = value

        if common_prefix:
            new_node_key = self._persist_node(new_node)
            return [compute_extension_key(common_prefix), new_node_key]
        else:
            return new_node

    def _get_branch_node(self, node, trie_key):
        if not trie_key:
            return node[16]
        else:
            sub_node = self._get_node(node[trie_key[0]])
            return self._get(sub_node, trie_key[1:])

    def _get_kv_node(self, node, trie_key):
        current_key = extract_key(node)
        node_type = get_node_type(node)

        if node_type == NODE_TYPE_LEAF:
            if trie_key == current_key:
                return node[1]
            else:
                return BLANK_NODE
        elif node_type == NODE_TYPE_EXTENSION:
            if key_starts_with(trie_key, current_key):
                sub_node = self._get_node(node[1])
                return self._get(sub_node, trie_key[len(current_key):])
            else:
                return BLANK_NODE
        else:
            raise Exception("Invariant: unreachable code path")

    def _getany(self, node, reverse=False, path=[]):
        # print('getany', node, 'reverse=', reverse, path)
        node_type = get_node_type(node)
        if node_type == NODE_TYPE_BLANK:
            return None
        if node_type == NODE_TYPE_BRANCH:
            if node[16] and not reverse:
                # print('found!', [16], path)
                return [16]
            scan_range = list(range(16))
            if reverse:
                scan_range.reverse()
            for i in scan_range:
                o = self._getany(
                    self._get_node(
                        node[i]),
                    reverse=reverse,
                    path=path + [i])
                if o is not None:
                    # print('found@', [i] + o, path)
                    return [i] + o
            if node[16] and reverse:
                # print('found!', [16], path)
                return [16]
            return None
        curr_key = list(remove_nibbles_terminator(decode_nibbles(node[0])))
        if node_type == NODE_TYPE_LEAF:
            # print('found#', curr_key, path)
            return curr_key

        if node_type == NODE_TYPE_EXTENSION:
            sub_node = self._get_node(node[1])
            return curr_key + \
                self._getany(sub_node, reverse=reverse, path=path + curr_key)

    def _iter(self, node, key, reverse=False, path=[]):
        # print('iter', node, key, 'reverse =', reverse, 'path =', path)
        node_type = get_node_type(node)

        if node_type == NODE_TYPE_BLANK:
            return None

        elif node_type == NODE_TYPE_BRANCH:
            # print('b')
            if len(key):
                sub_node = self._get_node(node[key[0]])
                o = self._iter(sub_node, key[1:], reverse, path + [key[0]])
                if o is not None:
                    # print('returning', [key[0]] + o, path)
                    return [key[0]] + o
            if reverse:
                scan_range = reversed(list(range(key[0] if len(key) else 0)))
            else:
                scan_range = list(range(key[0] + 1 if len(key) else 0, 16))
            for i in scan_range:
                sub_node = self._get_node(node[i])
                # print('prelim getany', path+[i])
                o = self._getany(sub_node, reverse, path + [i])
                if o is not None:
                    # print('returning', [i] + o, path)
                    return [i] + o
            if reverse and key and node[16]:
                # print('o')
                return [16]
            return None

        descend_key = list(remove_nibbles_terminator(decode_nibbles(node[0])))
        if node_type == NODE_TYPE_LEAF:
            if reverse:
                # print('L', descend_key, key, descend_key if descend_key < key else None, path)
                return descend_key if descend_key < key else None
            else:
                # print('L', descend_key, key, descend_key if descend_key > key else None, path)
                return descend_key if descend_key > key else None

        if node_type == NODE_TYPE_EXTENSION:
            # traverse child nodes
            sub_node = self._get_node(node[1])
            sub_key = key[len(descend_key):]
            # print('amhere', key, descend_key, descend_key > key[:len(descend_key)])
            if key_starts_with(key, descend_key):
                o = self._iter(sub_node, sub_key, reverse, path + descend_key)
            elif descend_key > key[:len(descend_key)] and not reverse:
                # print(1)
                # print('prelim getany', path+descend_key)
                o = self._getany(sub_node, False, path + descend_key)
            elif descend_key < key[:len(descend_key)] and reverse:
                # print(2)
                # print('prelim getany', path+descend_key)
                o = self._getany(sub_node, True, path + descend_key)
            else:
                o = None
            # print('returning@', descend_key + o if o else None, path)
            return descend_key + o if o else None

    def next(self, key):
        # print('nextting')
        key = list(bytes_to_nibbles(key))
        o = self._iter(self.root_node, key)
        # print('answer', o)
        return nibbles_to_bytes(remove_nibbles_terminator(o)) if o else None

    def prev(self, key):
        # print('prevving')
        key = list(bytes_to_nibbles(key))
        o = self._iter(self.root_node, key, reverse=True)
        # print('answer', o)
        return nibbles_to_bytes(remove_nibbles_terminator(o)) if o else None

    #
    # Dictionary API
    #
    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def __delitem__(self, key):
        return self.delete(key)

    def __contains__(self, key):
        return self.exists(key)
