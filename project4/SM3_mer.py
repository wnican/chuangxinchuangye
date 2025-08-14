import bisect
import struct
import time
from typing import List, Tuple, Optional
from SM3_Optimized import SM3_Optimized

class MerkleTree:
    
    def __init__(self, data: List[bytes]):
        self.sm3 = SM3_Optimized()
        # 存储原始数据用于验证
        self.original_data = data
        # 对叶子节点哈希并排序
        self.leaves = sorted([self._hash_leaf(leaf) for leaf in data])
        self.tree = self._build_tree(self.leaves)
        self.root = self.tree[-1][0] if self.tree else b''
    
    def _hash_leaf(self, leaf: bytes) -> bytes:
        return self.sm3.sm3_hash(b'\x00' + leaf)
    
    def _concat_and_hash(self, a: bytes, b: bytes) -> bytes:
        return self.sm3.sm3_hash(b'\x01' + a + b)
    
    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        if not leaves:
            return []
        
        tree = [leaves]
        current_level = leaves
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1] if i+1 < len(current_level) else left
                next_level.append(self._concat_and_hash(left, right))
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_root(self) -> bytes:
        return self.root
    
    def get_proof(self, index: int) -> List[bytes]:
        """修正的存在性证明"""
        if index < 0 or index >= len(self.original_data):
            raise IndexError("Leaf index out of range")
        
        # 获取原始数据对应的叶子哈希
        leaf_hash = self._hash_leaf(self.original_data[index])
        # 在排序后的叶子列表中找到位置
        pos = bisect.bisect_left(self.leaves, leaf_hash)
        if pos >= len(self.leaves) or self.leaves[pos] != leaf_hash:
            raise ValueError("Leaf not found in tree")
        
        proof = []
        current_pos = pos
        
        for level in self.tree[:-1]:
            sibling_pos = current_pos - 1 if current_pos % 2 else current_pos + 1
            if 0 <= sibling_pos < len(level):
                proof.append(level[sibling_pos])
            current_pos = current_pos // 2
        
        return proof
    
    def verify_proof(self, leaf: bytes, proof: List[bytes], index: int) -> bool:
        """修正的验证方法"""
        leaf_hash = self._hash_leaf(leaf)
        current_hash = leaf_hash
        current_pos = bisect.bisect_left(self.leaves, leaf_hash)
        
        if current_pos >= len(self.leaves) or self.leaves[current_pos] != leaf_hash:
            return False
        
        for sibling_hash in proof:
            if current_pos % 2 == 1:
                current_hash = self._concat_and_hash(sibling_hash, current_hash)
            else:
                current_hash = self._concat_and_hash(current_hash, sibling_hash)
            current_pos = current_pos // 2
        
        return current_hash == self.root
    
    def get_non_inclusion_proof(self, leaf: bytes) -> Tuple[Tuple[Optional[int], Optional[int]], Tuple[List[bytes], List[bytes]]]:
        
        leaf_hash = self._hash_leaf(leaf)
        pos = bisect.bisect_left(self.leaves, leaf_hash)
        
        left_neighbor = pos - 1 if pos > 0 else None
        right_neighbor = pos if pos < len(self.leaves) else None
        
        # 获取原始数据索引
        left_orig_idx = self.original_data.index(self.original_data[left_neighbor]) if left_neighbor is not None else None
        right_orig_idx = self.original_data.index(self.original_data[right_neighbor]) if right_neighbor is not None else None
        
        left_proof = self.get_proof(left_orig_idx) if left_orig_idx is not None else []
        right_proof = self.get_proof(right_orig_idx) if right_orig_idx is not None else []
        
        return (left_orig_idx, right_orig_idx), (left_proof, right_proof)
    
    def verify_non_inclusion(self, leaf: bytes, neighbors: Tuple[Optional[int], Optional[int]], 
                           proofs: Tuple[List[bytes], List[bytes]]) -> bool:
        """修正的验证方法"""
        leaf_hash = self._hash_leaf(leaf)
        (left_idx, right_idx), (left_proof, right_proof) = neighbors, proofs
        
        # 验证左邻居
        if left_idx is not None:
            left_leaf = self._hash_leaf(self.original_data[left_idx])
            if left_leaf >= leaf_hash:
                return False
            if not self.verify_proof(self.original_data[left_idx], left_proof, left_idx):
                return False
        
        # 验证右邻居
        if right_idx is not None:
            right_leaf = self._hash_leaf(self.original_data[right_idx])
            if right_leaf <= leaf_hash:
                return False
            if not self.verify_proof(self.original_data[right_idx], right_proof, right_idx):
                return False
        
        # 验证连续性
        if left_idx is not None and right_idx is not None:
            if right_idx != left_idx + 1:
                return False
        elif left_idx is None and right_idx != 0:
            return False
        elif right_idx is None and left_idx != len(self.original_data) - 1:
            return False
        
        return True

def generate_test_data(n: int = 100000) -> List[bytes]:
    """生成不重复的测试数据"""
    import random
    import string
    data = set()
    while len(data) < n:
        data.add(''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode())
    return list(data)

def main():
    # 生成测试数据
    print("生成测试数据...")
    data = generate_test_data(10000)  # 先用1万数据测试
    test_leaf = data[5000] if len(data) > 5000 else data[0]
    
    # 构建Merkle树
    print("构建Merkle树...")
    start = time.time()
    tree = MerkleTree(data)
    print(f"构建完成，耗时: {time.time()-start:.2f}秒")
    print(f"Merkle根: {tree.get_root().hex()}")
    
    # 测试存在性证明
    print("\n测试存在性证明:")
    proof = tree.get_proof(5000)
    print(f"证明长度: {len(proof)}")
    is_valid = tree.verify_proof(test_leaf, proof, 5000)
    print(f"验证结果: {is_valid}")
    
    # 测试不存在性证明
    print("\n测试不存在性证明:")
    non_existent = b"nonexistent_leaf_value_1234567890"
    neighbors, proofs = tree.get_non_inclusion_proof(non_existent)
    print(f"邻居索引: {neighbors}")
    is_valid = tree.verify_non_inclusion(non_existent, neighbors, proofs)
    print(f"验证结果: {is_valid}")

if __name__ == "__main__":
    main()