from SM2_opt import SM2Optimized
from hashlib import sha256
import secrets

class SM2POC(SM2Optimized):
    def sign(self, priv_key, ZA, msg, k=None):
        """SM2签名算法"""
        if k is None:
            k = secrets.randbelow(self.n - 1) + 1
        
        # M = ZA || msg
        M = ZA + msg
        e = int.from_bytes(sha256(M).digest(), 'big') % self.n
        
        # 计算kG = (x1, y1)
        x1, y1 = self._scalar_mult(k, self.G)
        r = (e + x1) % self.n
        if r == 0 or r + k == self.n:
            return self.sign(priv_key, ZA, msg)  # 重新生成k
        
        # s = (1+dA)⁻¹ · (k - r·dA) mod n
        s_val = (1 + priv_key) % self.n
        inv_s = self._mod_inverse(s_val, self.n)
        s = (inv_s * (k - r * priv_key)) % self.n
        
        if s == 0:
            return self.sign(priv_key, ZA, msg)  # 重新生成k
        
        return r, s

def same_user_k_reuse_poc():
    sm2 = SM2POC()
    dA, PA = sm2.generate_keypair()
    
    # 计算ZA (简化版)
    ZA = sha256(b"1234567812345678").digest()  # 使用固定IDA
    
    # 两个不同消息
    M1 = b"Message 1"
    M2 = b"Message 2"
    
    # 使用相同k签名
    k = secrets.randbelow(sm2.n - 1) + 1
    r1, s1 = sm2.sign(dA, ZA, M1, k)
    r2, s2 = sm2.sign(dA, ZA, M2, k)
    
    # 推导私钥
    numerator = (s2 - s1) % sm2.n
    denominator = (s1 - s2 + r1 - r2) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    deduced_dA = (numerator * inv_denom) % sm2.n
    
    # 验证
    print("\n===== 同一个用户重复使用k =====")
    print(f"原始私钥: {hex(dA)[:20]}...")
    print(f"推导私钥: {hex(deduced_dA)[:20]}...")
    print("推导结果:", "成功" if dA == deduced_dA else "失败")

def different_user_same_k_poc():
    sm2 = SM2POC()
    
    # 用户A
    dA, PA = sm2.generate_keypair()
    ZA = sha256(b"UserA_ID").digest()
    
    # 用户B
    dB, PB = sm2.generate_keypair()
    ZB = sha256(b"UserB_ID").digest()
    
    # 相同的k
    k = secrets.randbelow(sm2.n - 1) + 1
    
    # 用户A签名
    M1 = b"Message from A"
    r1, s1 = sm2.sign(dA, ZA, M1, k)
    
    # 用户B签名
    M2 = b"Message from B"
    r2, s2 = sm2.sign(dB, ZB, M2, k)
    
    # 推导用户B的私钥
    k_val = (s1 * (1 + dA) + r1 * dA) % sm2.n
    numerator = (k_val - s2) % sm2.n
    denominator = (s2 + r2) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    deduced_dB = (numerator * inv_denom) % sm2.n
    
    # 验证
    print("\n===== 不同用户使用相同k =====")
    print(f"原始dB: {hex(dB)[:20]}...")
    print(f"推导dB: {hex(deduced_dB)[:20]}...")
    print("推导结果:", "成功" if dB == deduced_dB else "失败")

def same_dk_ecdsa_sm2_poc():
    sm2 = SM2POC()
    d, P = sm2.generate_keypair()
    k = secrets.randbelow(sm2.n - 1) + 1
    
    # ECDSA签名
    msg_ecdsa = b"ECDSA Message"
    e = int.from_bytes(sha256(msg_ecdsa).digest(), 'big') % sm2.n
    x1, _ = sm2._scalar_mult(k, sm2.G)
    r1 = x1 % sm2.n
    s1 = (sm2._mod_inverse(k, sm2.n) * (e + r1 * d)) % sm2.n
    
    # SM2签名
    ZA = sha256(b"SameUser_ID").digest()
    msg_sm2 = b"SM2 Message"
    r2, s2 = sm2.sign(d, ZA, msg_sm2, k)
    
    # 推导私钥d
    e_val = int.from_bytes(sha256(msg_ecdsa).digest(), 'big') % sm2.n
    s1_inv = sm2._mod_inverse(s1, sm2.n)
    
    numerator = (s2 - s1_inv * e_val) % sm2.n
    denominator = (s1_inv * r1 - s2 - r2) % sm2.n
    inv_denom = sm2._mod_inverse(denominator, sm2.n)
    deduced_d = (numerator * inv_denom) % sm2.n
    
    # 验证
    print("\n===== 相同d和k用于ECDSA和SM2 =====")
    print(f"原始私钥: {hex(d)[:20]}...")
    print(f"推导私钥: {hex(deduced_d)[:20]}...")
    print("推导结果:", "成功" if d == deduced_d else "失败")

if __name__ == "__main__":
    same_user_k_reuse_poc()
    different_user_same_k_poc()
    same_dk_ecdsa_sm2_poc()