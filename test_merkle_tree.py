import unittest
import merkle_tree

# tree with 4 leaves: hello1, hello2, hello3, hello4
# example generated using https://xorbin.com/tools/sha256-hash-calculator?utm_content=cmp-true
# 0ddf6171935ddea0e214b73bd5de1737f552172605e8fe998e8ccd88b9ceaf14 is 0hello1
# 060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c is 0hello2
# 0d8574d9f74533324d3a13b6aaa2e46bebac63443528c4eb5e849c0ab193e405 is 0hello3
# 7895ebddb39a350b721e7dc865d4ff82fd05e1b6113125dd9069523d07cbf313 is 0hello4
# 1 + hello1 & hello2: e8b474d251372922987b75bc96b9f4f6491a91852f936a5e567af7bf563fdd00
# 1 + hello3 & 0hello4: 08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc
# root: 71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81
# proof for hello1 is hello2, hello3 & hello4
# proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
# root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'

class TestMerkleTree(unittest.TestCase):
    
# ------------------- test root creation -------------------

    def test_hash(self):
        expected_hash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        self.assertEqual(merkle_tree.hash('hello'), expected_hash)
    
    def test_parent_creation(self):
        node1 = merkle_tree.Node(merkle_tree.hash('0hello1'))
        node2 = merkle_tree.Node(merkle_tree.hash('0hello2'))
        expected_parent_value = 'e8b474d251372922987b75bc96b9f4f6491a91852f936a5e567af7bf563fdd00'
        parent = merkle_tree.create_parent(node1, node2)
        self.assertEqual(parent.value, expected_parent_value)
        self.assertEqual(parent.left, node1)
        self.assertEqual(parent.right, node2)
        self.assertEqual(node1.parent, parent)
        self.assertEqual(node2.parent, parent)
    
    def test_constructor_with_power_of_2(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        expected_root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        m_t = merkle_tree.MerkleTree(values)
        self.assertEqual(m_t.root.value, expected_root_value)
    
    def test_constructor_with_no_power_of_two(self):
        # 0dummy is 1553bfbf04c68b449f70fef231c8fb3653348d5d1b378ba255a3632ba8e9a7b7
        # expected root is de656a2940136b0b6fc7046c07970e682c050e92f09474e3b4fa6050fcc5e0e3
        values = ['hello1', 'hello2', 'hello3']
        expected_root_value = 'de656a2940136b0b6fc7046c07970e682c050e92f09474e3b4fa6050fcc5e0e3'
        m_t = merkle_tree.MerkleTree(values)
        self.assertEqual(m_t.root.value, expected_root_value)

    def test_constructor_with_1_elem(self):
        values = ['hello1']
        expected_root_value = '0ddf6171935ddea0e214b73bd5de1737f552172605e8fe998e8ccd88b9ceaf14'
        m_t = merkle_tree.MerkleTree(values)
        self.assertEqual(m_t.root.value, expected_root_value)

# ------------------- test proof verification -------------------
    
    def test_proof_verification_correct_proof_1(self):
        # this is proof for hello1
        value = 'hello1'
        correct_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 0, correct_proof, root_value)
        self.assertTrue(result)

    def test_proof_verification_correct_proof_2(self):
        # this is proof for hello2
        value = 'hello2'
        correct_proof = ['0ddf6171935ddea0e214b73bd5de1737f552172605e8fe998e8ccd88b9ceaf14', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 1, correct_proof, root_value)
        self.assertTrue(result)

    def test_proof_verification_correct_proof_3(self):
        # this is proof for hello3
        value = 'hello3'
        correct_proof = ['7895ebddb39a350b721e7dc865d4ff82fd05e1b6113125dd9069523d07cbf313', 'e8b474d251372922987b75bc96b9f4f6491a91852f936a5e567af7bf563fdd00']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 2, correct_proof, root_value)
        self.assertTrue(result)

    def test_proof_verification_correct_proof_4(self):
        # this is proof for hello4
        value = 'hello4'
        correct_proof = ['0d8574d9f74533324d3a13b6aaa2e46bebac63443528c4eb5e849c0ab193e405','e8b474d251372922987b75bc96b9f4f6491a91852f936a5e567af7bf563fdd00']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 3, correct_proof, root_value)
        self.assertTrue(result)

    def test_proof_verification_index_out_of_bounds(self):
        # this is proof for hello1
        value = 'hello1'
        correct_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 4, correct_proof, root_value)
        self.assertFalse(result)

    def test_proof_verification_wrong_index_1(self):
        # this is proof for hello1
        value = 'hello1'
        correct_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 1, correct_proof, root_value)
        self.assertFalse(result)

    def test_proof_verification_wrong_index_2(self):
        # this is proof for hello1
        value = 'hello1'
        correct_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 3, correct_proof, root_value)
        self.assertFalse(result)

    def test_proof_verification_wrong_proof(self):
        value = 'hello1'
        # this is a proof that should not pass verification
        a_wrong_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '00000']
        root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        result = merkle_tree.verify_proof(value, 0, a_wrong_proof, root_value)
        self.assertFalse(result)

# ------------------- test proof creation -------------------

    def test_calculate_proof(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        proof = m_t.calculate_proof('hello1', 0)
        correct_proof = ['060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c', '08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        self.assertEqual(proof, correct_proof)

    def test_calculate_proof_wrong_index(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        proof = m_t.calculate_proof('hello1', 1)
        self.assertEqual(proof, [''])

    def test_calculate_proof_index_ofb(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        proof = m_t.calculate_proof('hello1', 5)
        self.assertEqual(proof, [''])

    def test_calculate_proof_wrong_element(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        proof = m_t.calculate_proof('hello2', 0)
        self.assertEqual(proof, [''])

# ------------------- test creation & verification -------------------

    def test_create_proof_and_verify(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        root = m_t.root.value
        for i in range(len(values)):
            proof = m_t.calculate_proof(values[i], i)
            result = merkle_tree.verify_proof(values[i], i, proof, root)
            self.assertTrue(result)

    def test_create_proof_and_verify_dummy_proof(self):
        # here we try to verify a proof-of-inclusion with the dummy proof ['']
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        root = m_t.root.value
        for i in range(len(values)):
            result = merkle_tree.verify_proof(values[i], i, [''], root)
            self.assertFalse(result)

# ------------------- test add value -------------------

    def test_add_value_1(self):
        values = ['hello1', 'hello2', 'hello3']
        expected_root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        m_t = merkle_tree.MerkleTree(values)
        m_t.add_value('hello4')
        self.assertEqual(m_t.root.value, expected_root_value)

    def test_add_value_2(self):
        values = ['hello1', 'hello2']
        expected_root_value = 'de656a2940136b0b6fc7046c07970e682c050e92f09474e3b4fa6050fcc5e0e3'
        m_t = merkle_tree.MerkleTree(values)
        m_t.add_value('hello3')
        self.assertEqual(m_t.root.value, expected_root_value)

# ------------------- test update value -------------------

    def test_concat(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t_1 = merkle_tree.MerkleTree(values[:2])
        m_t_2 = merkle_tree.MerkleTree(values[2:])
        m_t_1.concat(m_t_2)
        expected_root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        self.assertEqual(m_t_1.root.value, expected_root_value)

    def test_update_value_at_index(self):
        values = ['hello1', 'hello2', 'foo', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        m_t.update_value_at_index(2, 'hello3')
        expected_new_values = ['hello1', 'hello2', 'hello3', 'hello4']
        expected_root_value = '71f078927ddef28603d5643c605256264c2c579da5cd130031750a943b594d81'
        self.assertEqual(m_t.values, expected_new_values)
        self.assertEqual(m_t.root.value, expected_root_value)

    def test_update_value_at_index_error(self):
        with self.assertRaises(IndexError):
            values = ['hello1', 'hello2', 'hello3', 'hello4']
            m_t = merkle_tree.MerkleTree(values)
            m_t.update_value_at_index(5, 'bar')

    def test_try_second_preimage_attack(self):
        values = ['hello1', 'hello2', 'hello3', 'hello4']
        m_t = merkle_tree.MerkleTree(values)
        value = '0ddf6171935ddea0e214b73bd5de1737f552172605e8fe998e8ccd88b9ceaf14' + '060b699cd3bbab10c5282b338be984f251d53e5b273e35b8febf0753c95a044c'
        proof = ['08550280484db6ab61901306437f2484494cc8a1e0d78043a61daf24812f9bfc']
        root = m_t.root.value
        index = 0
        result = merkle_tree.verify_proof(value, index, proof, root)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
    
