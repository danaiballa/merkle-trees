import hashlib
import math


def hash(m: str) -> str:
    '''
    SHA256 hash of a string.
    '''
    h = hashlib.sha256()
    h.update(bytes(m, 'utf-8'))
    return str(h.digest().hex())


def verify_proof(value: str, proof: list[str], root: str) -> bool:
    '''
    Verify a Merkle Tree proof of inclusion.
    '''
    proof_length = len(proof)
    val_hash = hash(value)
    for i in range(proof_length):
        new_value = val_hash + proof[i]
        val_hash = hash(new_value)
    # line below might not be the best
    return (val_hash == root)


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
    
    def calculate_proof(self, elem) -> list[str]:
        '''
        Calculate Merkle Tree proof, for the first element appearing in the tree.
        '''
        # find index of element
        try:
            index = self.values.index(elem)
        except ValueError:
            print('Error: Element not in Merkle Tree, proof cannot be constructed.')
            raise
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

    # This function is not that useful. Someone that has the tree can verify inclusion without this function
    def verify_proof(self, value: str, proof: list[str]) -> bool:
        return verify_proof(value, proof, self.root.value)
    
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
            print('Error: Index out of range.')
            raise

    def update_value(self, value: str, new_value: str):
        '''
        Update the first appearing value with a new value.
        '''
        try:
            index = self.values.index(value)
            self.update_value_at_index(index, new_value)
        except ValueError:
            print('Error: Value does not belong to the tree.')
            raise

    def print(self):
        '''
        Helper that prints the tree, for debugging
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
