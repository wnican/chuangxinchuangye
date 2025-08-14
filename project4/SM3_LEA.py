import struct
from SM3_Optimized import SM3_Optimized

class SM3_Length_Extension_Attack:
    def __init__(self):
        self.sm3 = SM3_Optimized()
    
    def generate_padding(self, message_length):
        """生成给定长度的消息的填充字节"""
        pad_len = 64 - ((message_length + 8 + 1) % 64)
        if pad_len < 0:
            pad_len += 64
        
        padding = b'\x80' + b'\x00' * (pad_len - 1)
        padding += struct.pack('>Q', message_length * 8)
        
        return padding
    
    def extend_hash(self, original_hash_hex, original_length, extension_message):
        """
        执行长度扩展攻击
        :param original_hash_hex: 原始消息的哈希值(16进制字符串)
        :param original_length: 原始消息的字节长度
        :param extension_message: 要扩展的消息
        :return: (伪造的哈希值, 伪造的消息填充)
        """
        # 将原始哈希值转换为内部状态
        original_hash_bytes = bytes.fromhex(original_hash_hex)
        V = list(struct.unpack('>8I', original_hash_bytes))
        
        # 计算原始消息的填充
        padding = self.generate_padding(original_length)
        
        # 构造完整的伪造消息(实际应用中不知道原始消息，这里只是用于验证)
        forged_message_padding = padding + extension_message
        
        # 对扩展部分进行分组处理
        extension_with_padding = extension_message
        total_length = original_length + len(padding) + len(extension_message)
        
        # 添加扩展部分自己的填充(如果需要)
        if len(extension_with_padding) % 64 != 0:
            pad_len = 64 - (len(extension_with_padding) % 64)
            extension_with_padding += b'\x80' + b'\x00' * (pad_len - 1)
            extension_with_padding += struct.pack('>Q', total_length * 8)
        
        # 处理每个64字节块
        offset = 0
        while offset < len(extension_with_padding):
            block = extension_with_padding[offset:offset+64]
            if len(block) < 64:
                block += b'\x00' * (64 - len(block))
            
            W, W_ = self.sm3.message_expansion(block)
            V = self.sm3.compress_function(V, W, W_)
            offset += 64
        
        # 生成伪造的哈希值
        forged_hash = struct.pack('>8I', *V)
        
        return forged_hash.hex(), forged_message_padding
    
    def verify_attack(self, original_message, extension_message):
        """
        验证长度扩展攻击
        :param original_message: 原始消息
        :param extension_message: 扩展消息
        :return: (是否成功, 真实哈希, 伪造哈希)
        """
        # 计算原始哈希
        original_hash = self.sm3.sm3_hash_hex(original_message)
        original_length = len(original_message)
        
        # 执行攻击
        forged_hash, forged_padding = self.extend_hash(original_hash, original_length, extension_message)
        
        # 计算真实哈希(original_message || padding || extension_message)
        real_extended_message = original_message + forged_padding
        real_hash = self.sm3.sm3_hash_hex(real_extended_message)
        
        return forged_hash == real_hash, real_hash, forged_hash


if __name__ == "__main__":
    attack = SM3_Length_Extension_Attack()
    
    print("SM3长度扩展攻击验证")
    print("=" * 60)
    
    # 测试用例1
    original_msg = b"secret_data"
    extension_msg = b"&admin=1"
    success, real_hash, forged_hash = attack.verify_attack(original_msg, extension_msg)
    
    print(f"原始消息: {original_msg}")
    print(f"扩展消息: {extension_msg}")
    print(f"真实扩展哈希: {real_hash}")
    print(f"伪造扩展哈希: {forged_hash}")
    print(f"攻击是否成功: {'是' if success else '否'}")
    print("-" * 60)
    
    # 测试用例2 - 不同长度的消息
    test_cases = [
        (b"short", b"extension"),
        (b"exactly_56_bytes_____________________________", b"extend"),
        (b"exactly_64_bytes________________________________", b"ext"),
        (b"longer_than_64_bytes__________________________________________", b"ext")
    ]
    
    for original, extension in test_cases:
        success, real_hash, forged_hash = attack.verify_attack(original, extension)
        print(f"原始长度: {len(original)} 扩展长度: {len(extension)}")
        print(f"结果: {'成功' if success else '失败'}")
        print("-" * 60)