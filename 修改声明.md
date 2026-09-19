# 修改声明 / Modification Notice

本目录是 **[LC044/WeChatMsg（留痕）](https://github.com/LC044/WeChatMsg)** 的二次修改版本，
按 **GNU General Public License v3.0**（见 `LICENSE`）分发。

---

## 1. 上游信息

| 项目 | 内容 |
|---|---|
| 上游仓库 | https://github.com/LC044/WeChatMsg |
| 上游作者 | LC044（以及 [贡献者列表](https://github.com/lc044/wechatmsg/graphs/contributors)） |
| 上游许可证 | GPL-3.0 |
| 上游版本 | `app/config.py` 中 `version = '0.2.8'` |

本项目保留了上游的全部原始文件、版权声明与 `LICENSE`（未作任何删改），
所有修改都以**新增文件 / 最小侵入改动**的方式实现。

---

## 2. 本次修改内容

**目的**：让工具适配 **PC 微信 4.x**（实测 4.1.13.65）。上游代码只支持微信 3.x，
在 4.x 上会一直提示「检测不到微信运行 / 登录」，无法获取密钥与数据。

### 2.1 新增文件（全部为本次新增）

```
wx4/                        微信 4.x 适配层（新增，GPL-3.0 分发）
├── __init__.py
├── common.py               SQLCipher 4 参数与 HMAC-SHA512 校验
├── paths.py                4.x 安装路径 / xwechat_files / 账号目录探测
├── key.py                  从运行中的 Weixin.exe 内存提取数据库密钥
├── decrypt.py              快照、逐页 AES-256-CBC 解密、WAL 合并、校验重试
├── reader.py               会话·联系人·消息表映射、ZSTD 正文解码、消息类型解析
├── media.py                图片 .dat / 语音 silk / 视频 / 文件导出
├── export.py               TXT / CSV / JSON / HTML 导出与索引页
├── cli.py                  python -m wx4 命令行
├── gui.py                  PyQt5 图形界面
├── __main__.py
doc/微信4.x适配说明.md        适配原理、数据结构对照、用法、限制、排错
doc/修改声明.md              本文件
tools/privacy_scan.py        发布前隐私扫描脚本
tools/debug_msg.py           单条消息解析诊断脚本
```

### 2.2 被修改的上游文件（仅 4 个，改动均为最小侵入）

| 文件 | 改动 |
|---|---|
| `main.py` | 入口增加「检测到 4.x 数据目录 → 打开新导出界面」的分支；3.x 流程（`loadPCDecryptView` / `loadMainWinView`）**原样保留** |
| `readme.md` | 顶部增加 4.x 使用提示；`PC版微信` 章节新增「0. 新版微信 4.x」小节 |
| `requirements.txt` | 新增 `zstandard>=0.22.0`（4.x 消息正文是 ZSTD 压缩） |
| `.gitignore` | 新增对 `wx4_keys.json`、`app/DataBase/decrypted|export` 等运行产物的忽略（防止密钥被误提交） |

### 2.3 未改动的上游核心代码

`app/` 下除上述 `.gitignore`/依赖之外的**所有代码均未修改**，包括原有的
`app/decrypt/get_wx_info.py`（微信 3.x 解密流程）——它现在作为 3.x 环境的回退路径继续存在。

---

## 3. 许可与合规

1. 本项目整体按 **GPL-3.0** 分发，`LICENSE` 为上游原文件，未作修改。
2. 新增文件（`wx4/`、`doc/微信4.x适配说明.md`、`tools/privacy_scan.py`、
   `tools/debug_msg.py`、本文件）同样以 **GPL-3.0** 授权，不附加任何额外限制。
3. 本项目**不收取任何费用**，不提供任何担保（见 GPL-3.0 第 15、16 条）。
4. 分发时请保留 `LICENSE`、本声明文件与上游作者的署名信息。
5. 上游 `readme.md` 中的「致谢」「支持该项目」「联系方式」等章节保持原样，
   以便使用者能找到原作者并支持上游项目。

---

## 4. 免责声明（沿用上游立场）

本项目有且仅有一个目的：**「留痕」——我的数据我做主**。
前提是「我的数据」，其次才是「我做主」。

* 本工具只用于导出**使用者自己设备上、自己账号**的聊天记录
* 禁止任何人以任何形式将其用于非法用途
* 本工具不会修改微信的任何数据，不会影响微信的正常使用，也不能找回已删除的聊天记录
* 对于使用本程序所造成的任何后果，所有创作者不承担任何责任

---

## 5. 与上游的关系说明

本修改版**不是**上游官方版本，也未获得上游作者的背书。
`wx4/` 适配层由本次修改的贡献者独立实现，与上游代码库是并列关系：

* 上游仓库继续维护其 3.x / 官方 4.x 实现
* 本修改版专注于「在 4.x 上能实际跑通取密钥 + 解密 + 导出」这一条链路

如果上游已经提供了等效或更好的 4.x 支持，**建议优先使用上游版本**。

---

## 6. 技术来源与致谢

4.x 适配层的实现参考了以下公开的技术资料与开源实现（均在各自仓库的许可下使用）：

* [PyWxDump](https://github.com/xaoyaoo/PyWxDump)（上游 readme 已致谢；该项目已于 2025-10 删除）
* [wcdb-key-tool](https://github.com/TANGandXUE/wcdb-key-tool) — Windows 4.1+ `Config.Cipher` 只读扫描思路
* [看雪论坛《wx新版本（after 4.0）数据库 key 逆向》](https://bbs.kanxue.com/thread-287761-1.htm) — WCDB `setCipherKey` 结构
* [SQLCipher 官方设计文档](https://www.zetetic.net/sqlcipher/design/) — SQLCipher 4 页结构与 KDF 参数
* [ZedeX/weixin-decrypte-script](https://github.com/ZedeX/weixin-decrypte-script) — 4.x 库结构与 `.dat` 格式整理
* [WeChatMsg](https://github.com/LC044/WeChatMsg) — 本项目的基础

具体到每一处结论的来源，见 `doc/微信4.x适配说明.md`。
