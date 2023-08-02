import hashlib
import math

# TODO: pep8

def hash(m: str) -> str:
    h = hashlib.sha256()
    h.update(bytes(m, 'utf-8'))
    return str(h.digest().hex())

def verify_proof(val: str, proof: list[str], root: str) -> bool:
    proof_length = len(proof)
    val_hash = hash(val)
    for i in range(proof_length):
        new_value = val_hash + proof[i]
        val_hash = hash(new_value)
    # line below might not be the best
    return (val_hash == root)

class Node:
    
    # TODO: decide if we should have Node(hash(str)) or Node(str) and hash calculated internally
    def __init__(self, value, parent = None, left = None, right = None):
        self.value = value
        # TODO: perhaps we don't need to store self.parent
        self.parent = parent
        self.left = left
        self.right = right


def create_parent(left: Node, right: Node) -> Node:
    parent = Node(hash(left.value + right.value))
    left.parent = parent
    right.parent = parent
    parent.left = left
    parent.right = right
    return parent   


class MerkleTree:
    
    def __init__(self, values: list[str]):
        self.values = values
        self.__create_leaves(values)
        self.number = len(values)
        self.root = self.__construct()

    def __create_leaves(self, values: list[str]) -> list[Node]:
        self.leaves = []
        for value in values:
            self.leaves.append(Node(hash(value)))

    def __construct(self) -> Node:
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
        number_of_leaves = len(self.leaves)
        log = math.log2(number_of_leaves)
        # if not a power of 2
        if math.floor(log) != log:
            closest_power_of_two = int(2 ** (math.floor(log) + 1)) # number of leaves it should have
            to_append = closest_power_of_two - number_of_leaves # number of leaves to be added (dummy values)
            self.leaves += [Node(hash('dummy')) for i in range(to_append)]
            self.values += ['dummy' for i in range(to_append)]
    
    def calculate_proof(self, elem) -> list[str]:
        # find index of element
        # TODO: we don't need the index, but we need to check inclusion, fix this
        try:
            index = self.values.index(elem)
        except ValueError:
            print('Error: Element not in Merkle Tree, proof cannot be constructed!')
            return
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

    def verify_proof(self, val: str, proof: list[str]) -> bool:
        return verify_proof(val, proof, self.root.value)
    
    # TODO: add_value, remove_value            
