import random
from collections import defaultdict
from hashlib import sha256
from phe import paillier  # pip install phe
from ecdsa import NIST256p, SigningKey  # pip install ecdsa

class GPCProtocol:
    def __init__(self):
        # 初始化椭圆曲线 (NIST P-256)
        self.curve = NIST256p
        self.generator = self.curve.generator
        self.order = self.curve.order

    def hash_to_scalar(self, item: bytes) -> int:
        """将输入哈希到椭圆曲线标量域"""
        hashed = sha256(item).digest()
        return int.from_bytes(hashed, 'big') % self.order

    def client_round1(self, passwords: list) -> tuple:
        """客户端第一轮：生成盲化密码和临时密钥"""
        self.client_passwords = passwords
        self.k1 = random.randint(1, self.order - 1)  # 客户端密钥
        
        # 计算 H(pwd)^k1
        blinded_passwords = []
        self.hashed_passwords = []
        for pwd in passwords:
            s = self.hash_to_scalar(pwd)
            point = s * self.generator
            blinded_point = self.k1 * point
            blinded_passwords.append(blinded_point)
            self.hashed_passwords.append(point)
        
        # 打乱顺序
        random.shuffle(blinded_passwords)
        return blinded_passwords

    def server_round2(self, blinded_passwords: list, leaked_db: list) -> tuple:
        """服务器第二轮：处理盲化密码并返回加密结果"""
        self.leaked_db = leaked_db  # [(password, count)]
        self.k2 = random.randint(1, self.order - 1)  # 服务器密钥
        
        # 生成Paillier密钥
        self.pub_key, self.priv_key = paillier.generate_paillier_keypair()
        
        # 计算 { H(vi)^(k1·k2) }
        double_blinded = [self.k2 * point for point in blinded_passwords]
        random.shuffle(double_blinded)
        
        # 计算 { (H(wj)^k2, Enc(tj)) }
        encrypted_records = []
        self.server_points = []
        for pwd, count in leaked_db:
            s = self.hash_to_scalar(pwd)
            point = s * self.generator
            blinded_point = self.k2 * point
            enc_count = self.pub_key.encrypt(count)
            encrypted_records.append((blinded_point, enc_count))
            self.server_points.append(point)
        
        random.shuffle(encrypted_records)
        return double_blinded, encrypted_records, self.pub_key

    def client_round3(self, double_blinded, encrypted_records, pub_key):
        """客户端第三轮：计算交集和泄露统计"""
        # 计算 { H(wj)^(k1·k2) }
        server_set = {}
        for point, enc_count in encrypted_records:
            server_point = self.k1 * point  # (k1·k2)·H(wj)
            server_set[server_point] = enc_count
        
        # 计算交集和泄露统计
        intersection = []
        total_encrypted = pub_key.encrypt(0)
        
        for i, point in enumerate(double_blinded):
            if point in server_set:
                pwd = self.client_passwords[i]
                intersection.append(pwd)
                total_encrypted += server_set[point]
        
        return intersection, total_encrypted, len(intersection)

    def server_decrypt(self, encrypted_sum):
        """服务器解密聚合结果"""
        return self.priv_key.decrypt(encrypted_sum)

# 测试用例
if __name__ == "__main__":
    # 初始化协议
    protocol = GPCProtocol()
    
    # 模拟数据
    client_passwords = [
        b"password123",
        b"securePass!",
        b"qwertyuiop",
        b"letmein2023"
    ]
    
    leaked_database = [
        (b"password123", 1500),   # 泄露1500次
        (b"admin123", 50000),
        (b"qwertyuiop", 8000),
        (b"welcome1", 12000)
    ]
    
    # 协议执行
    # 客户端第一轮
    blinded_pwds = protocol.client_round1(client_passwords)
    
    # 服务器第二轮
    double_blinded, enc_records, pub_key = protocol.server_round2(
        blinded_pwds, leaked_database
    )
    
    # 客户端第三轮
    intersection, enc_sum, count = protocol.client_round3(
        double_blinded, enc_records, pub_key
    )
    
    # 服务器解密
    total_leaks = protocol.server_decrypt(enc_sum)
    
    # 打印结果
    print(f"交集大小 (泄露密码数量): {count}")
    print(f"总泄露次数: {total_leaks}")
    print("泄露的密码:")
    for pwd in intersection:
        print(f"- {pwd.decode()}")

    # 验证结果
    expected_leaked = [b"password123", b"qwertyuiop"]
    assert set(intersection) == set(expected_leaked)
    
    expected_count = 1500 + 8000
    assert total_leaks == expected_count