import hashlib
import math
import secrets


def hash(m: str) -> str:
    '''
    SHA256 hash of a string.
    '''
    h = hashlib.sha256()
    h.update(bytes(m, 'utf-8'))
    return str(h.digest().hex())


def verify_proof(value: str, index: int, proof: list[str], root_value: str) -> bool:
    '''
    Verify a Merkle Tree proof of inclusion.

    Indexing starts at 0.
    '''

    # Make sure index is not out of bounds.
    max_index = 2**len(proof) - 1
    if index > max_index: return False

    cur_hash = hash(value)
    for elem in proof:
        if index % 2 == 0: # even number, so value is a left child
            cur_hash = hash(cur_hash + elem)
        else:
            cur_hash = hash(elem + cur_hash) 
        index = index // 2
    return secrets.compare_digest(cur_hash, root_value)


class Node:
    '''
    Node of a (doubly linked) binary tree.
    '''
    def __init__(self, value, parent=None, left=None, right=None):
        self.value = value
        self.parent = parent
        self.left = left
        self.right = right


def create_parent(left: Node, right: Node) -> Node:
    '''
    Given two Nodes, calculate, set and return their parent.
    '''
    parent = Node(hash(left.value + right.value))
    left.parent = parent
    right.parent = parent
    parent.left = left
    parent.right = right
    return parent   


class MerkleTree:
    def __init__(self, values: list[str]):
        self.values = values
        # number of non-dummy values
        self.non_dummy = len(values)
        self.__create_leaves()
        self.root = self.__construct()

    def __create_leaves(self) -> list[Node]:
        '''
        Create the leaves of a Merkle Tree.
        '''
        self.leaves = []
        for value in self.values:
            self.leaves.append(Node(hash(value)))

    def __construct(self) -> Node:
        '''
        Construct a Merkle Tree.
        - calculate levels
        - set root
        '''
        self.__pad()
        cur_level = self.leaves
        while len(cur_level) > 1:
            next_level = []
            for i in range(0, len(cur_level), 2):
                node_left = cur_level[i]
                node_right = cur_level[i+1]
                next_level.append(create_parent(node_left, node_right))
            cur_level = next_level
        [root] = cur_level
        return root
    
    def __pad(self):
        '''
        Make number of leaves a power of 2 by adding dummy values.
        '''
        number_of_leaves = len(self.leaves)
        log = math.log2(number_of_leaves)
        # if not a power of 2
        if math.floor(log) != log:
            closest_power_of_two = int(2 ** (math.floor(log) + 1)) # number of leaves it should have
            to_append = closest_power_of_two - number_of_leaves # number of leaves to be added (dummy values)
            self.leaves += [Node(hash('dummy')) for i in range(to_append)]
    
    def calculate_proof(self, index: int) -> list[str]:
        '''
        Calculate Merkle Tree proof.
        '''
        proof = []
        node = self.leaves[index]
        while node.parent:
            parent = node.parent
            if node == parent.left:
                proof.append(parent.right.value)
            else:
                proof.append(parent.left.value)
            node = parent
        return proof
    
    def concat(self, other_tree) -> Node:
        '''
        Concatenate two Merkle Trees.

        Trees should have the same number of leaves (and be padded).

        Returns new root.
        '''
        left_root = self.root
        right_root = other_tree.root
        parent = create_parent(left_root, right_root)
        self.root = parent
        self.leaves += other_tree.leaves
        self.values += other_tree.values
        self.non_dummy += other_tree.non_dummy
    
    def add_value(self, value: str):
        '''
        Add value to Merkle Tree (create new leaf).
        '''
        # if non-dummy values are already a power of 2
        # so tree is full
        if (self.non_dummy == len(self.leaves)):
            # construct a new merkle tree and concatenate the two
            new_tree = MerkleTree([value] + ['dummy' for i in range(len(self.leaves) - 1)])
            # concat new tree to old tree
            self.concat(new_tree)
        else:
            # replace a dummy value with the new value
            index = self.non_dummy
            self.leaves[index].value = hash(value)
            self.values.append(value)
            self.non_dummy += 1
            # re-calculate hashes
            node = self.leaves[index]
            while node.parent:
                parent = node.parent
                if node == parent.left:
                    parent.value = hash(node.value + parent.right.value)
                else:
                    parent.value = hash(parent.left.value + node.value)
                node = node.parent

    def update_value_at_index(self, index: int, new_value: str):
        '''
        Update the value at a given index.
        '''
        try:
            # update values
            self.values[index] = new_value
            # update node and path up to root
            node = self.leaves[index]
            node.value = hash(new_value)
            while node.parent:
                parent = node.parent
                if node == parent.left:
                    parent.value = hash(node.value + parent.right.value)
                else:
                    parent.value = hash(parent.left.value + node.value)
                node = parent
        except IndexError:
            raise IndexError('Index out of range')

    def print(self):
        '''
        Print all levels of the tree.
        '''
        cur_level = self.leaves
        to_print = []
        while cur_level:
            cur_level_vals = [node.value for node in cur_level]
            to_print.append(cur_level_vals)
            # construct next level
            next_level = []
            for i in range(0, len(cur_level), 2):
                node = cur_level[i]
                if node.parent:
                    next_level.append(node.parent)
            cur_level = next_level
        to_print.reverse()
        for level in to_print:
            print(level)
