# -*- coding: utf-8 -*-
"""
wx4 —— PC 微信 4.x (Weixin.exe) 聊天记录导出适配层

旧版工具（app.decrypt.get_wx_info）依赖 WeChat 3.x 的
`WeChat.exe` + `WeChatWin.dll` + `WeChat Files\\<wxid>\\Msg\\*.db` 结构，
在微信 4.x 上完全失效：

    * 进程名        WeChat.exe        -> Weixin.exe
    * 主模块        WeChatWin.dll     -> Weixin.dll（且不再是可枚举的普通模块）
    * 数据目录      WeChat Files      -> xwechat_files\\<wxid>_<4hex>\\db_storage
    * 数据库命名    MSG0.db/MicroMsg  -> message_0.db / contact.db / session.db ...
    * 加密算法      SQLCipher3        -> SQLCipher4（SHA512 / 256000 轮 / 保留区 80B）
    * 密钥获取      内存里明文 raw key -> 4.1+ 只在内存里留 Config.Cipher 对象

本包用微信 4.x 的方式重新实现「取密钥 -> 解密 -> 读取 -> 导出」全链路。
"""
__version__ = "4.0.0"
