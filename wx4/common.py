# -*- coding: utf-8 -*-
"""微信 4.x 数据库加解密通用常量与校验函数。

微信 4.x 使用 SQLCipher 4 参数：

    页大小          4096
    KDF             PBKDF2-HMAC-SHA512，迭代 256000，输出 32 字节
    HMAC            HMAC-SHA512，mac_key = PBKDF2(enc_key, salt^0x3A, 2)
    每页保留区      80 字节 = IV(16) + HMAC(64)
    第 1 页         前 16 字节为 salt，其后为加密数据
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import struct

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80              # IV(16) + HMAC(64)
KDF_ITER = 256000
SQLITE_HDR = b"SQLite format 3\x00"

# 旧的 WeChat 3.x / SQLCipher3 参数，仅用于兼容识别
LEGACY_PAGE_SZ = 4096
LEGACY_ITER = 64000
LEGACY_RESERVE_SZ = 48


def derive_enc_key(passphrase: bytes, salt: bytes) -> bytes:
    """从 passphrase + 库自身 salt 派生该库的 AES-256 密钥。"""
    return hashlib.pbkdf2_hmac("sha512", passphrase, salt, KDF_ITER, dklen=KEY_SZ)


def hmac_for_page1(enc_key: bytes, page1: bytes) -> bytes:
    """算出第一页应当匹配的 HMAC-SHA512 值。"""
    salt = page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)
    hm = hmac_mod.new(mac_key, page1[SALT_SZ:PAGE_SZ - RESERVE_SZ + IV_SZ], hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest()


def verify_enc_key(enc_key: bytes, page1: bytes) -> bool:
    """用第一页的 HMAC 校验密钥是否真的能解密这个库。"""
    if len(page1) < PAGE_SZ:
        return False
    return hmac_for_page1(enc_key, page1) == page1[PAGE_SZ - HMAC_SZ:PAGE_SZ]


def is_sqlcipher4(page1: bytes) -> bool:
    """判断文件看起来是不是微信 4.x 的加密库（非明文、非 3.x）。"""
    if len(page1) < PAGE_SZ:
        return False
    if page1[:16] == SQLITE_HDR:
        return False
    return True
