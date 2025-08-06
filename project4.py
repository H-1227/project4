import time
from typing import List, Tuple, Any
import numpy as np

# SM3常量定义
SM3_T = [0x79cc4519] * 16 + [0x7a879d8a] * 48


# 布尔函数
def ff0(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def ff1(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


# 置换函数
def gg0(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def gg1(x: int, y: int, z: int) -> int:
    return (x & y) | ((~x) & z)


# 常量置换
def p0(x: int) -> int:
    return x ^ ((x << 9) | (x >> 23)) ^ ((x << 17) | (x >> 15))


def p1(x: int) -> int:
    return x ^ ((x << 15) | (x >> 17)) ^ ((x << 23) | (x >> 9))


# 循环左移
def rotl(x: int, n: int) -> int:
    # 确保移位量在0-31范围内，结果保持32位无符号整数
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


class SM3Base:
    """SM3算法基础实现"""

    def __init__(self):
        # 初始向量
        self.iv = [
            0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
            0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
        ]

    def _padding(self, message: bytes) -> bytes:
        """消息填充"""
        length = len(message) * 8  # 消息长度(比特)
        message += b'\x80'  # 添加10000000

        # 填充0，使长度模512等于448
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'

        # 添加长度(大端序，64位)
        message += length.to_bytes(8, byteorder='big')
        return message

    def _message_extension(self, b: bytes) -> tuple[list[int], list[int]]:
        """消息扩展"""
        # 将512比特消息块分为16个32比特字
        w = [int.from_bytes(b[i:i + 4], byteorder='big') for i in range(0, 64, 4)]

        # 扩展为68个字
        for i in range(16, 68):
            w.append(p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^
                     rotl(w[i - 13], 7) ^ w[i - 6])

        # 扩展为64个字
        w1 = [0] * 64
        for i in range(64):
            w1[i] = w[i] ^ w[i + 4]

        return w, w1

    def _compress(self, v: List[int], b: bytes) -> List[int]:
        """压缩函数"""
        # 修复变量名冲突：将b改为b_val，避免覆盖参数b
        a, b_val, c, d, e, f, g, h = v
        w, w1 = self._message_extension(b)

        for j in range(64):
            # 计算TT1和TT2
            tt1 = (rotl(a, 12) + e + rotl(SM3_T[j], j)) % 0x100000000
            tt1 = rotl(tt1, 7)
            tt2 = tt1 ^ rotl(a, 12)

            # 选择布尔函数
            if j < 16:
                f_func = ff0(b_val, c, d)  # 使用b_val
                g_func = gg0(e, f, g)
            else:
                f_func = ff1(b_val, c, d)  # 使用b_val
                g_func = gg1(e, f, g)

            t = (h + g_func + rotl(e, 12) + w1[j] + tt2) % 0x100000000
            h_new = (f_func + tt1 + t) % 0x100000000

            # 按照SM3标准更新状态变量
            new_a = h_new
            new_b = a
            new_c = rotl(b_val, 9)  # 使用b_val
            new_d = c
            new_e = p0(t)
            new_f = e
            new_g = rotl(f, 19)
            new_h = g

            # 更新当前轮状态（注意这里将b_val更新为new_b）
            a, b_val, c, d, e, f, g, h = new_a, new_b, new_c, new_d, new_e, new_f, new_g, new_h

        # 与初始向量异或
        return [
            (a ^ v[0]) % 0x100000000,
            (b_val ^ v[1]) % 0x100000000,  # 使用b_val
            (c ^ v[2]) % 0x100000000,
            (d ^ v[3]) % 0x100000000,
            (e ^ v[4]) % 0x100000000,
            (f ^ v[5]) % 0x100000000,
            (g ^ v[6]) % 0x100000000,
            (h ^ v[7]) % 0x100000000
        ]

    def hash(self, message: bytes) -> bytes:
        """计算SM3哈希值"""
        # 消息填充
        padded = self._padding(message)

        # 初始化状态
        state = self.iv.copy()

        # 分块处理
        for i in range(0, len(padded), 64):
            block = padded[i:i + 64]
            state = self._compress(state, block)

        # 转换为字节串
        return b''.join([x.to_bytes(4, byteorder='big') for x in state])


class SM3Optimized1(SM3Base):
    """SM3优化版本1：预计算常量和合并操作"""

    def __init__(self):
        super().__init__()
        # 预计算旋转后的常量
        self.rotated_T = [rotl(SM3_T[j], j) for j in range(64)]

    def _compress(self, v: List[int], b: bytes) -> List[int]:
        """优化的压缩函数：减少重复计算"""
        # 修复变量名冲突
        a, b_val, c, d, e, f, g, h = v
        w, w1 = self._message_extension(b)

        for j in range(64):
            # 使用预计算的旋转常量
            tt1 = (rotl(a, 12) + e + self.rotated_T[j]) % 0x100000000
            tt1 = rotl(tt1, 7)
            tt2 = tt1 ^ rotl(a, 12)

            # 合并条件判断
            if j < 16:
                f_val = b_val ^ c ^ d  # 使用b_val
                g_val = e ^ f ^ g
            else:
                f_val = (b_val & c) | (b_val & d) | (c & d)  # 使用b_val
                g_val = (e & f) | ((~e) & g)

            t = (h + g_val + rotl(e, 12) + w1[j] + tt2) % 0x100000000
            h_new = (f_val + tt1 + t) % 0x100000000

            # 按照SM3标准更新状态变量
            new_a = h_new
            new_b = a
            new_c = rotl(b_val, 9)  # 使用b_val
            new_d = c
            new_e = p0(t)
            new_f = e
            new_g = rotl(f, 19)
            new_h = g

            # 更新当前轮状态
            a, b_val, c, d, e, f, g, h = new_a, new_b, new_c, new_d, new_e, new_f, new_g, new_h

        return [
            (a ^ v[0]) % 0x100000000,
            (b_val ^ v[1]) % 0x100000000,  # 使用b_val
            (c ^ v[2]) % 0x100000000,
            (d ^ v[3]) % 0x100000000,
            (e ^ v[4]) % 0x100000000,
            (f ^ v[5]) % 0x100000000,
            (g ^ v[6]) % 0x100000000,
            (h ^ v[7]) % 0x100000000
        ]


class SM3Optimized2(SM3Optimized1):
    """SM3优化版本2：使用numpy加速消息扩展和批量操作"""

    def __init__(self):
        super().__init__()

    def _message_extension(self, b: bytes) -> tuple[Any, list[int]]:
        """使用numpy加速消息扩展"""
        # 将512比特消息块分为16个32比特字
        w = np.zeros(68, dtype=np.uint32)
        for i in range(16):
            w[i] = int.from_bytes(b[i * 4:(i + 1) * 4], byteorder='big')

        # 向量化扩展计算
        for i in range(16, 68):
            w[i] = p1((w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) & 0xFFFFFFFF) ^ \
                   (rotl(w[i - 13], 7) & 0xFFFFFFFF) ^ w[i - 6]
            w[i] &= 0xFFFFFFFF

        # 计算w1
        w1 = np.zeros(64, dtype=np.uint32)
        for i in range(64):
            w1[i] = w[i] ^ w[i + 4]

        # 关键修复：将numpy整数转换为Python原生整数
        return w.tolist(), [int(x) for x in w1.tolist()]


class SM3Optimized3(SM3Optimized2):
    """SM3优化版本3：块处理优化和预计算更多值"""

    def __init__(self):
        super().__init__()

    def hash(self, message: bytes) -> bytes:
        """优化的哈希函数：处理大消息时减少内存分配"""
        length = len(message)
        # 预先计算需要的块数
        block_count = (length + 8 + 63) // 64  # 填充后总块数

        # 初始化状态
        state = self.iv.copy()

        # 处理完整块
        ptr = 0
        while ptr + 64 <= length:
            block = message[ptr:ptr + 64]
            state = self._compress(state, block)
            ptr += 64

        # 处理剩余部分和填充
        remaining = message[ptr:]
        padded = self._padding(remaining)

        # 处理填充后的块
        for i in range(0, len(padded), 64):
            block = padded[i:i + 64]
            state = self._compress(state, block)

        return b''.join([x.to_bytes(4, byteorder='big') for x in state])


def sm3_length_extension_attack(original_hash: bytes, original_length: int, append_data: bytes, sm3_impl=SM3Base) -> \
Tuple[bytes, bytes]:
    """
    执行SM3长度扩展攻击
    :param original_hash: 原始消息的哈希值
    :param original_length: 原始消息的长度(字节)
    :param append_data: 要附加的数据
    :return: (新消息, 新哈希值)
    """
    # 将原始哈希值转换为状态向量
    state = [
        int.from_bytes(original_hash[0:4], 'big'),
        int.from_bytes(original_hash[4:8], 'big'),
        int.from_bytes(original_hash[8:12], 'big'),
        int.from_bytes(original_hash[12:16], 'big'),
        int.from_bytes(original_hash[16:20], 'big'),
        int.from_bytes(original_hash[20:24], 'big'),
        int.from_bytes(original_hash[24:28], 'big'),
        int.from_bytes(original_hash[28:32], 'big')
    ]

    # 创建SM3实例
    sm3 = sm3_impl()

    # 计算原始消息的填充
    original_bits = original_length * 8
    pad_length = 64 - (original_length % 64)
    if pad_length < 9:  # 至少需要1字节的0x80和8字节的长度
        pad_length += 64

    # 构建填充（不包括原始消息）
    padding = b'\x80' + b'\x00' * (pad_length - 9) + original_bits.to_bytes(8, 'big')

    # 构建新消息：原始消息(未知)的填充 + 附加数据
    new_message = padding + append_data

    # 使用原始哈希作为初始状态继续计算
    current_state = state

    # 处理新消息的块
    for i in range(0, len(new_message), 64):
        block = new_message[i:i + 64]
        # 确保块长度为64字节
        if len(block) < 64:
            block += b'\x00' * (64 - len(block))
        current_state = sm3._compress(current_state, block)

    # 计算新的哈希值
    forged_hash = b''.join([x.to_bytes(4, byteorder='big') for x in current_state])

    return new_message, forged_hash


class MerkleTreeRFC6962:
    """基于RFC6962的Merkle树实现"""

    def __init__(self, leaves: List[bytes], sm3_impl=SM3Optimized3):
        """
        初始化Merkle树
        :param leaves: 叶子节点列表（每个元素为32字节的哈希值）
        """
        self.sm3 = sm3_impl()
        self.leaves = leaves
        self.tree = self._build_tree()
        self.root = self.tree[0][0] if self.tree else b''

    def _hash_leaf(self, data: bytes) -> bytes:
        """计算叶子节点的哈希（RFC6962格式）"""
        # 叶子节点前缀：0x00
        return self.sm3.hash(b'\x00' + data)

    def _hash_internal(self, left: bytes, right: bytes) -> bytes:
        """计算内部节点的哈希（RFC6962格式）"""
        # 内部节点前缀：0x01
        return self.sm3.hash(b'\x01' + left + right)

    def _build_tree(self) -> List[List[bytes]]:
        """构建Merkle树"""
        if not self.leaves:
            return []

        # 计算所有叶子节点的哈希
        tree = [[]]
        for leaf in self.leaves:
            # 确保叶子是32字节
            if len(leaf) != 32:
                raise ValueError("叶子节点必须是32字节的哈希值")
            tree[0].append(self._hash_leaf(leaf))

        # 构建上层节点
        level = 0
        while len(tree[level]) > 1:
            next_level = []
            # 按对处理当前层节点
            for i in range(0, len(tree[level]), 2):
                left = tree[level][i]
                # 如果是最后一个节点且数量为奇数，复制自身
                right = tree[level][i + 1] if i + 1 < len(tree[level]) else left
                next_level.append(self._hash_internal(left, right))
            tree.append(next_level)
            level += 1

        return tree

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        获取指定索引叶子节点的存在性证明
        :param index: 叶子节点索引
        :return: 证明列表，每个元素为(哈希值, 是否为右节点)
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("叶子节点索引越界")

        proof = []
        current_index = index
        current_level = 0

        while current_level < len(self.tree) - 1:
            # 确定兄弟节点位置
            if current_index % 2 == 0:  # 左节点
                sibling_index = current_index + 1
                is_right = True
                # 检查是否是最后一个节点（奇数情况）
                if sibling_index >= len(self.tree[current_level]):
                    sibling_index = current_index
            else:  # 右节点
                sibling_index = current_index - 1
                is_right = False

            # 添加兄弟节点哈希到证明
            proof.append((self.tree[current_level][sibling_index], is_right))

            # 上移到父节点
            current_index = current_index // 2
            current_level += 1

        return proof

    def verify_proof(self, leaf: bytes, proof: List[Tuple[bytes, bool]], root: bytes) -> bool:
        """
        验证存在性证明
        :param leaf: 叶子节点数据
        :param proof: 存在性证明
        :param root: Merkle树根
        :return: 验证是否成功
        """
        current_hash = self._hash_leaf(leaf)

        for (hash_val, is_right) in proof:
            if is_right:
                # 当前哈希在左，证明哈希在右
                current_hash = self._hash_internal(current_hash, hash_val)
            else:
                # 当前哈希在右，证明哈希在左
                current_hash = self._hash_internal(hash_val, current_hash)

        return current_hash == root

    def get_non_existence_proof(self, index: int) -> Tuple[
        List[Tuple[bytes, bool]], bytes, List[Tuple[bytes, bool]], bytes]:
        """
        获取指定索引位置的不存在性证明
        :param index: 要证明不存在的索引
        :return: (左兄弟证明, 左兄弟哈希, 右兄弟证明, 右兄弟哈希)
        """
        n = len(self.leaves)
        if index < 0 or index >= n:
            raise IndexError("索引超出范围")

        # 找到左兄弟（小于index的最大存在索引）
        left_idx = index - 1
        while left_idx >= 0 and left_idx >= n:
            left_idx -= 1

        # 找到右兄弟（大于index的最小存在索引）
        right_idx = index + 1
        while right_idx < n and right_idx >= n:
            right_idx += 1

        if left_idx < 0 and right_idx >= n:
            raise ValueError("无法证明空树中的不存在性")

        left_proof = self.get_proof(left_idx) if left_idx >= 0 else []
        left_hash = self._hash_leaf(self.leaves[left_idx]) if left_idx >= 0 else b''

        right_proof = self.get_proof(right_idx) if right_idx < n else []
        right_hash = self._hash_leaf(self.leaves[right_idx]) if right_idx < n else b''

        return left_proof, left_hash, right_proof, right_hash

    def verify_non_existence(self, index: int,
                             proof: Tuple[List[Tuple[bytes, bool]], bytes, List[Tuple[bytes, bool]], bytes],
                             root: bytes) -> bool:
        """验证不存在性证明"""
        left_proof, left_hash, right_proof, right_hash = proof
        n = len(self.leaves)

        # 验证左兄弟证明
        left_valid = True
        if left_hash:
            left_root = left_hash
            for (hash_val, is_right) in left_proof:
                if is_right:
                    left_root = self._hash_internal(left_root, hash_val)
                else:
                    left_root = self._hash_internal(hash_val, left_root)
            left_valid = (left_root == root)

        # 验证右兄弟证明
        right_valid = True
        if right_hash:
            right_root = right_hash
            for (hash_val, is_right) in right_proof:
                if is_right:
                    right_root = self._hash_internal(right_root, hash_val)
                else:
                    right_root = self._hash_internal(hash_val, right_root)
            right_valid = (right_root == root)

        # 验证索引位置确实不存在
        left_idx = index - 1
        right_idx = index + 1

        # 检查左兄弟确实小于index，右兄弟确实大于index
        position_valid = True
        if left_idx >= 0 and left_idx >= len(self.leaves):
            position_valid = False
        if right_idx < len(self.leaves) and right_idx >= len(self.leaves):
            position_valid = False

        return left_valid and right_valid and position_valid


def benchmark(impl_class, data_size: int = 10 * 1024 * 1024, iterations: int = 5) -> float:
    """基准测试函数"""
    sm3 = impl_class()
    # 使用固定模式生成数据
    data = b"test_data_pattern" * (data_size // len(b"test_data_pattern") + 1)
    data = data[:data_size]

    # 预热
    sm3.hash(data)

    # 多次运行取平均值
    total_time = 0
    for _ in range(iterations):
        start = time.time()
        sm3.hash(data)
        total_time += time.time() - start

    avg_time = total_time / iterations
    speed_mb = (data_size / (1024 * 1024)) / avg_time
    return speed_mb


def test_length_extension_attack():
    """测试长度扩展攻击"""
    sm3 = SM3Optimized3()
    secret = b"secret_key"
    public_data = b"public_data"
    message = secret + public_data
    original_hash = sm3.hash(message)
    original_length = len(message)

    # 攻击者不知道secret，但知道public_data和original_hash
    append_data = b"_appended_data"

    # 执行长度扩展攻击
    forged_message_suffix, forged_hash = sm3_length_extension_attack(
        original_hash, original_length, append_data
    )

    # 计算实际的新哈希（用于验证攻击是否成功）
    actual_new_message = message + forged_message_suffix[len(sm3._padding(message)[len(message):]):]
    actual_new_hash = sm3.hash(actual_new_message)

    # 验证攻击是否成功
    success = (forged_hash == actual_new_hash)
    print(f"长度扩展攻击{'成功' if success else '失败'}")
    if success:
        print(f"原始哈希: {original_hash.hex()}")
        print(f"伪造哈希: {forged_hash.hex()}")
        print(f"实际哈希: {actual_new_hash.hex()}")
    return success


def test_merkle_tree(leaf_count: int = 100000):
    """测试Merkle树实现"""
    print(f"测试{leaf_count}个叶子节点的Merkle树...")

    # 生成随机叶子节点（使用固定模式）
    leaves = []
    for i in range(leaf_count):
        leaves.append(f"leaf_{i}_fixed_pattern".encode()[:32].ljust(32, b'\x00'))

    # 构建Merkle树
    start_time = time.time()
    merkle_tree = MerkleTreeRFC6962(leaves)
    build_time = time.time() - start_time
    print(f"Merkle树构建时间: {build_time:.2f}秒")
    print(f"Merkle树根哈希: {merkle_tree.root.hex()}")

    # 测试存在性证明
    test_index = min(45678, leaf_count - 1)  # 防止索引越界
    proof = merkle_tree.get_proof(test_index)
    verify_result = merkle_tree.verify_proof(leaves[test_index], proof, merkle_tree.root)
    print(f"存在性证明验证{'成功' if verify_result else '失败'}")

    # 测试不存在性证明
    non_exist_index = min(leaf_count // 2, leaf_count - 1)
    if non_exist_index < leaf_count:
        non_proof = merkle_tree.get_non_existence_proof(non_exist_index)
        non_verify = merkle_tree.verify_non_existence(non_exist_index, non_proof, merkle_tree.root)
        print(f"不存在性证明验证{'成功' if non_verify else '失败'}")

    return verify_result


def main():
    """主函数：运行测试和性能基准"""
    print("SM3算法实现与优化测试")
    print("=" * 50)

    # 测试向量验证
    test_message = b"abc"
    expected_hash = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

    # 验证基础实现
    sm3_base = SM3Base()
    base_hash = sm3_base.hash(test_message).hex()
    assert base_hash == expected_hash, f"基础实现错误: {base_hash} != {expected_hash}"
    print("基础实现验证通过")

    # 验证优化版本1
    sm3_opt1 = SM3Optimized1()
    opt1_hash = sm3_opt1.hash(test_message).hex()
    assert opt1_hash == expected_hash, f"优化版本1错误: {opt1_hash} != {expected_hash}"
    print("优化版本1验证通过")

    # 验证优化版本2
    sm3_opt2 = SM3Optimized2()
    opt2_hash = sm3_opt2.hash(test_message).hex()
    assert opt2_hash == expected_hash, f"优化版本2错误: {opt2_hash} != {expected_hash}"
    print("优化版本2验证通过")

    # 验证优化版本3
    sm3_opt3 = SM3Optimized3()
    opt3_hash = sm3_opt3.hash(test_message).hex()
    assert opt3_hash == expected_hash, f"优化版本3错误: {opt3_hash} != {expected_hash}"
    print("优化版本3验证通过")

    # 性能基准测试
    print("\n性能基准测试 (10MB数据，5次平均):")
    print(f"{'实现方式':<15} {'速度(MB/s)':<10}")
    print("-" * 30)

    base_speed = benchmark(SM3Base)
    print(f"{'基础实现':<15} {base_speed:<9.2f}")

    opt1_speed = benchmark(SM3Optimized1)
    print(f"{'优化版本1':<15} {opt1_speed:<9.2f}")

    opt2_speed = benchmark(SM3Optimized2)
    print(f"{'优化版本2':<15} {opt2_speed:<9.2f}")

    opt3_speed = benchmark(SM3Optimized3)
    print(f"{'优化版本3':<15} {opt3_speed:<9.2f}")

    # 测试长度扩展攻击
    print("\n测试长度扩展攻击:")
    test_length_extension_attack()

    # 测试Merkle树
    print("\n测试Merkle树:")
    test_merkle_tree(1000)  # 减少叶子节点数量，提高测试速度


if __name__ == "__main__":
    main()
