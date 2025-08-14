import struct
import time
from SM3 import SM3
class SM3_Optimized:
    def __init__(self):
        # 初始化IV值
        self.IV = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ]
        
        # 预计算常量T
        self.T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
        
        # 预计算位移量
        self.ROTATE_AMOUNTS = {
            7: 7, 9: 9, 12: 12, 15: 15, 17: 17, 19: 19
        }
    
    @staticmethod
    def rotate_left(x, n):
        """优化的32位循环左移，确保n不为负"""
        n = n % 32  # 确保位移量在0-31范围内
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    def _ff(self, X, Y, Z, j):
        """内联布尔函数FF"""
        if j < 16:
            return X ^ Y ^ Z
        return (X & Y) | (X & Z) | (Y & Z)
    
    def _gg(self, X, Y, Z, j):
        """内联布尔函数GG"""
        if j < 16:
            return X ^ Y ^ Z
        return (X & Y) | (~X & Z)
    
    def _p0(self, X):
        """内联置换函数P0"""
        return X ^ self.rotate_left(X, 9) ^ self.rotate_left(X, 17)
    
    def _p1(self, X):
        """内联置换函数P1"""
        return X ^ self.rotate_left(X, 15) ^ self.rotate_left(X, 23)
    
    def padding(self, message):
        """优化的消息填充"""
        length = len(message)
        bit_length = length * 8
        
        # 计算需要填充的字节数
        pad_len = 64 - ((length + 8 + 1) % 64)
        if pad_len < 0:
            pad_len += 64
        
        # 预分配填充后的消息空间
        padded_msg = bytearray(length + 1 + pad_len + 8)
        padded_msg[:length] = message
        padded_msg[length] = 0x80
        
        # 添加长度(64位大端序)
        padded_msg[length+1+pad_len:] = struct.pack('>Q', bit_length)
        
        return padded_msg
    
    def message_expansion(self, block):
        """优化的消息扩展"""
        W = [0] * 68
        W_ = [0] * 64
        
        # 使用struct.unpack快速解析16个32位字
        words = struct.unpack('>16I', block)
        W[:16] = words
        
        # 展开循环以减少函数调用
        for j in range(16, 68):
            w3_rot = self.rotate_left(W[j-3], 15)
            w13_rot = self.rotate_left(W[j-13], 7)
            term = W[j-16] ^ W[j-9] ^ w3_rot
            W[j] = self._p1(term) ^ w13_rot ^ W[j-6]
        
        # 生成W'
        for j in range(64):
            W_[j] = W[j] ^ W[j+4]
        
        return W, W_
    
    def compress_function(self, V, W, W_):
        """优化的压缩函数，修复位移错误"""
        A, B, C, D, E, F, G, H = V
        
        # 展开部分循环，减少条件判断
        for j in range(64):
            # 确保位移量不为负
            rotate_amount = j % 32  # j mod 32确保在0-31范围内
            
            # 计算SS1
            a_rot12 = self.rotate_left(A, 12)
            t_rot = self.rotate_left(self.T[j], rotate_amount)
            ss1_temp = (a_rot12 + E + t_rot) & 0xFFFFFFFF
            ss1 = self.rotate_left(ss1_temp, 7)
            
            # 计算SS2
            ss2 = ss1 ^ a_rot12
            
            # 计算TT1和TT2
            tt1 = (self._ff(A, B, C, j) + D + ss2 + W_[j]) & 0xFFFFFFFF
            tt2 = (self._gg(E, F, G, j) + H + ss1 + W[j]) & 0xFFFFFFFF
            
            # 更新寄存器值
            D = C
            C = self.rotate_left(B, 9)
            B = A
            A = tt1
            H = G
            G = self.rotate_left(F, 19)
            F = E
            E = self._p0(tt2)
        
        return [A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3],
                E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]]
    
    def sm3_hash(self, message):
        """优化的哈希计算"""
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("Message must be bytes or bytearray")
        
        # 消息填充
        padded_msg = self.padding(message)
        
        # 初始化变量
        V = self.IV.copy()
        
        # 处理消息分组
        for i in range(0, len(padded_msg), 64):
            block = padded_msg[i:i+64]
            W, W_ = self.message_expansion(block)
            V = self.compress_function(V, W, W_)
        
        # 输出哈希值
        return struct.pack('>8I', *V)
    
    def sm3_hash_hex(self, message):
        """返回16进制哈希字符串"""
        return self.sm3_hash(message).hex()


def benchmark():
    """性能测试函数"""
    sm3_orig = SM3()  # 原始实现
    sm3_opt = SM3_Optimized()  # 优化实现
    
    # 测试数据
    test_data = b'a' * (1024 * 1024)  # 1MB数据
    
    # 测试原始实现
    start = time.time()
    sm3_orig.sm3_hash(test_data)
    orig_time = time.time() - start
    
    # 测试优化实现
    start = time.time()
    sm3_opt.sm3_hash(test_data)
    opt_time = time.time() - start
    
    print(f"原始实现耗时: {orig_time:.4f}秒")
    print(f"优化实现耗时: {opt_time:.4f}秒")
    print(f"性能提升: {orig_time/opt_time:.2f}倍")


if __name__ == "__main__":
    # 验证正确性
    sm3 = SM3_Optimized()
    test_vectors = [
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    ]
    
    print("正确性验证:")
    for msg, expected in test_vectors:
        result = sm3.sm3_hash_hex(msg)
        print(f"输入: {msg}")
        print(f"预期: {expected}")
        print(f"结果: {result}")
        print(f"状态: {'通过' if result == expected else '失败'}")
        print("-" * 50)
    
    # 性能测试
    print("\n性能测试:")
    benchmark()
    benchmark()