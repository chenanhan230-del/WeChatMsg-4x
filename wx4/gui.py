# -*- coding: utf-8 -*-
"""微信 4.x 导出助手（PyQt5 界面）。

老版 `app/ui/tool/pc_decrypt` 只认微信 3.x（WeChat.exe / WeChatWin.dll /
WeChat Files\\<wxid>\\Msg），在 4.x 上点「获取信息」永远拿不到东西。这个窗口
是老版界面的 4.x 替代品，功能对齐：

    检测微信 -> 提取密钥 -> 解密数据库 -> 浏览会话 -> 导出记录
"""
from __future__ import annotations

import os
import sys
import traceback

from PyQt5.QtCore import QThread, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,
                             QComboBox, QFileDialog, QGroupBox, QHBoxLayout,
                             QHeaderView, QLabel, QLineEdit, QMessageBox,
                             QProgressBar, QPushButton, QTableWidget,
                             QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget)

from . import decrypt as dec
from . import export as exp
from . import key as keymod
from . import paths
from .reader import open_data

DEFAULT_KEY_FILE = "wx4_keys.json"
DEFAULT_DECRYPT_DIR = "app/DataBase/decrypted"
DEFAULT_EXPORT_DIR = "app/DataBase/export"


# ---------------------------------------------------------------------------
# 后台线程
# ---------------------------------------------------------------------------
class ExtractKeyThread(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)

    def __init__(self, db_storage, key_file):
        super().__init__()
        self.db_storage = db_storage
        self.key_file = key_file

    def run(self):
        try:
            ex = keymod.KeyExtractor(self.db_storage, progress=self.log.emit)
            ex.extract(save_to=self.key_file)
            ok = bool(ex.keys)
            self.done.emit(ok, "%d/%d 个数据库已拿到密钥"
                           % (len(ex.keys), len(ex.salt_index)))
        except Exception as e:                            # noqa: BLE001
            self.log.emit(traceback.format_exc())
            self.done.emit(False, str(e))


class DecryptThread(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    done = pyqtSignal(bool, str)

    def __init__(self, keys, db_storage, out_dir):
        super().__init__()
        self.keys = keys
        self.db_storage = db_storage
        self.out_dir = out_dir

    def run(self):
        try:
            total = len(self.keys)
            self.progress.emit(0, total)
            res = dec.decrypt_all(self.keys, self.db_storage, self.out_dir,
                                  progress=self.log.emit)
            self.done.emit(bool(res["ok"]),
                           "成功 %d，失败 %d" % (len(res["ok"]), len(res["failed"])))
        except Exception as e:                            # noqa: BLE001
            self.log.emit(traceback.format_exc())
            self.done.emit(False, str(e))


class ExportThread(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)

    def __init__(self, decrypted_dir, export_dir, fmt, wxid, session=None):
        super().__init__()
        self.decrypted_dir = decrypted_dir
        self.export_dir = export_dir
        self.fmt = fmt
        self.wxid = wxid
        self.session = session

    def run(self):
        try:
            data = open_data(self.decrypted_dir, self.wxid, progress=self.log.emit)
            res = exp.export_all(data, self.export_dir, fmt=self.fmt,
                                 sessions=[self.session] if self.session else None,
                                 progress=self.log.emit)
            if self.fmt == "html" and not self.session:
                exp.export_index(data, self.export_dir, progress=self.log.emit)
            data.close()
            self.done.emit(bool(res["exported"]),
                           "已导出 %d 个会话" % len(res["exported"]))
        except Exception as e:                            # noqa: BLE001
            self.log.emit(traceback.format_exc())
            self.done.emit(False, str(e))


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class Wx4ExportWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("微信 4.x 聊天记录导出（留痕 · 适配版）")
        self.resize(1000, 720)
        self.accounts: list[dict] = []
        self.data = None
        self._thread = None
        self._build()
        self.refresh_env()

    # -- 界面 -------------------------------------------------------------
    def _build(self):
        root = QVBoxLayout(self)

        # 环境
        env_box = QGroupBox("1. 微信检测")
        env_layout = QVBoxLayout(env_box)
        row = QHBoxLayout()
        self.lbl_env = QLabel("正在检测…")
        self.lbl_env.setWordWrap(True)
        row.addWidget(self.lbl_env, 1)
        btn_refresh = QPushButton("重新检测")
        btn_refresh.clicked.connect(self.refresh_env)
        row.addWidget(btn_refresh)
        env_layout.addLayout(row)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("账号："))
        self.cmb_account = QComboBox()
        self.cmb_account.currentIndexChanged.connect(self._on_account)
        row2.addWidget(self.cmb_account, 1)
        env_layout.addLayout(row2)
        root.addWidget(env_box)

        # 密钥
        key_box = QGroupBox("2. 获取密钥（从运行中的微信进程内存读取，需要微信处于登录状态）")
        key_layout = QVBoxLayout(key_box)
        row3 = QHBoxLayout()
        self.btn_key = QPushButton("获取密钥")
        self.btn_key.clicked.connect(self.extract_key)
        row3.addWidget(self.btn_key)
        row3.addWidget(QLabel("密钥文件："))
        self.edit_keyfile = QLineEdit(DEFAULT_KEY_FILE)
        row3.addWidget(self.edit_keyfile, 1)
        key_layout.addLayout(row3)
        self.lbl_key = QLabel("尚未获取")
        self.lbl_key.setWordWrap(True)
        key_layout.addWidget(self.lbl_key)
        root.addWidget(key_box)

        # 解密
        dec_box = QGroupBox("3. 解密数据库")
        dec_layout = QVBoxLayout(dec_box)
        row4 = QHBoxLayout()
        self.btn_decrypt = QPushButton("开始解密")
        self.btn_decrypt.clicked.connect(self.start_decrypt)
        row4.addWidget(self.btn_decrypt)
        row4.addWidget(QLabel("输出目录："))
        self.edit_outdir = QLineEdit(DEFAULT_DECRYPT_DIR)
        row4.addWidget(self.edit_outdir, 1)
        btn_pick = QPushButton("选择…")
        btn_pick.clicked.connect(lambda: self._pick_dir(self.edit_outdir))
        row4.addWidget(btn_pick)
        dec_layout.addLayout(row4)
        self.bar = QProgressBar()
        dec_layout.addWidget(self.bar)
        root.addWidget(dec_box)

        # 会话 + 导出
        sess_box = QGroupBox("4. 会话列表与导出")
        sess_layout = QVBoxLayout(sess_box)
        row5 = QHBoxLayout()
        self.btn_load = QPushButton("加载会话")
        self.btn_load.clicked.connect(self.load_sessions)
        row5.addWidget(self.btn_load)
        self.chk_only_msg = QCheckBox("只看有消息的会话")
        self.chk_only_msg.setChecked(True)
        self.chk_only_msg.stateChanged.connect(self.fill_sessions)
        row5.addWidget(self.chk_only_msg)
        row5.addWidget(QLabel("格式："))
        self.cmb_fmt = QComboBox()
        self.cmb_fmt.addItems(list(exp.EXPORTERS))
        row5.addWidget(self.cmb_fmt)
        row5.addWidget(QLabel("导出到："))
        self.edit_exportdir = QLineEdit(DEFAULT_EXPORT_DIR)
        row5.addWidget(self.edit_exportdir, 1)
        self.btn_export = QPushButton("导出全部")
        self.btn_export.clicked.connect(lambda: self.export(session=None))
        row5.addWidget(self.btn_export)
        self.btn_export_one = QPushButton("导出选中")
        self.btn_export_one.clicked.connect(self.export_selected)
        row5.addWidget(self.btn_export_one)
        self.btn_open = QPushButton("打开导出目录")
        self.btn_open.clicked.connect(self.open_export_dir)
        row5.addWidget(self.btn_open)
        sess_layout.addLayout(row5)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["有消息", "会话名", "wxid", "最后消息", "摘要"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.doubleClicked.connect(lambda _i: self._show_preview())
        sess_layout.addWidget(self.table)
        root.addWidget(sess_box, 1)

        # 日志
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setMinimumHeight(120)
        root.addWidget(self.text)

    # -- 工具 -------------------------------------------------------------
    def _pick_dir(self, line_edit):
        d = QFileDialog.getExistingDirectory(self, "选择目录", line_edit.text() or ".")
        if d:
            line_edit.setText(d)

    def log(self, msg):
        self.text.append(str(msg))
        QApplication.processEvents()

    def open_export_dir(self):
        d = os.path.abspath(self.edit_exportdir.text() or DEFAULT_EXPORT_DIR)
        if not os.path.isdir(d):
            QMessageBox.information(self, "提示", "目录还不存在：%s" % d)
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(d))

    # -- 环境检测 ---------------------------------------------------------
    def refresh_env(self):
        try:
            desc = paths.describe()
        except Exception as e:                            # noqa: BLE001
            self.lbl_env.setText("检测失败：%s" % e)
            return
        procs = keymod.find_weixin_processes()
        self.accounts = desc["accounts"]
        lines = [
            "微信安装目录：%s" % (desc["install_path"] or "未检测到"),
            "数据目录：%s" % (desc["xwechat_root"] or "未检测到"),
            "微信进程：%s" % (", ".join("PID=%d（%d MB）" % (p["pid"], p["mem_kb"] // 1024)
                                        for p in procs) if procs else "未运行（请先启动并登录微信）"),
        ]
        self.lbl_env.setText("\n".join(lines))
        self.cmb_account.blockSignals(True)
        self.cmb_account.clear()
        for a in self.accounts:
            n = len(dec.list_encrypted(a["db_storage"]))
            self.cmb_account.addItem("%s（%d 个数据库）" % (a["dir_name"], n), a)
        self.cmb_account.blockSignals(False)
        if not self.accounts:
            self.lbl_env.setText(self.lbl_env.text()
                                 + "\n未找到任何账号目录，请确认微信已登录过。")

    def _on_account(self, _idx):
        self.data = None
        self.table.setRowCount(0)

    def current_account(self):
        a = self.cmb_account.currentData()
        if not a and self.accounts:
            a = self.accounts[0]
        return a

    # -- 密钥 -------------------------------------------------------------
    def extract_key(self):
        acc = self.current_account()
        if not acc:
            QMessageBox.critical(self, "错误", "没有可用的账号目录")
            return
        if not keymod.find_weixin_processes():
            QMessageBox.critical(self, "错误", "没有检测到微信进程\n请先启动并登录微信")
            return
        self.btn_key.setEnabled(False)
        self.lbl_key.setText("正在扫描微信进程内存…")
        self._thread = ExtractKeyThread(acc["db_storage"], self.edit_keyfile.text())
        self._thread.log.connect(self.log)
        self._thread.done.connect(self._key_done)
        self._thread.start()

    def _key_done(self, ok, msg):
        self.btn_key.setEnabled(True)
        self.lbl_key.setText(("密钥获取成功：" if ok else "密钥获取失败：") + msg)
        if ok:
            QMessageBox.information(self, "成功", "密钥已保存到 %s\n\n%s"
                                    % (self.edit_keyfile.text(), msg))
        else:
            QMessageBox.critical(self, "失败", msg)

    # -- 解密 -------------------------------------------------------------
    def start_decrypt(self):
        acc = self.current_account()
        kf = self.edit_keyfile.text()
        if not acc:
            QMessageBox.critical(self, "错误", "没有可用的账号目录")
            return
        if not os.path.exists(kf):
            QMessageBox.critical(self, "错误", "找不到密钥文件 %s\n请先点『获取密钥』" % kf)
            return
        keys = {k: v for k, v in keymod.load_keys(kf).items() if not k.startswith("_")}
        if not keys:
            QMessageBox.critical(self, "错误", "密钥文件里没有可用密钥")
            return
        self.btn_decrypt.setEnabled(False)
        self.bar.setRange(0, len(keys))
        self.bar.setValue(0)
        self._thread = DecryptThread(keys, acc["db_storage"], self.edit_outdir.text())
        self._thread.log.connect(self.log)
        self._thread.progress.connect(lambda v, t: (self.bar.setRange(0, t),
                                                    self.bar.setValue(v)))
        self._thread.done.connect(self._decrypt_done)
        self._thread.start()

    def _decrypt_done(self, ok, msg):
        self.btn_decrypt.setEnabled(True)
        self.bar.setValue(self.bar.maximum())
        if ok:
            QMessageBox.information(self, "解密完成", msg)
            self.load_sessions()
        else:
            QMessageBox.critical(self, "解密失败", msg)

    # -- 会话 -------------------------------------------------------------
    def load_sessions(self):
        d = self.edit_outdir.text()
        acc = self.current_account()
        wxid = acc["wxid"] if acc else ""
        if not os.path.isdir(d):
            QMessageBox.critical(self, "错误", "解密目录不存在：%s" % d)
            return
        try:
            self.data = open_data(d, wxid, progress=self.log)
        except Exception as e:                            # noqa: BLE001
            QMessageBox.critical(self, "错误", "读取失败：%s" % e)
            return
        self.fill_sessions()

    def fill_sessions(self):
        if self.data is None:
            return
        only = self.chk_only_msg.isChecked()
        rows = []
        for s in self.data.sessions():
            has = self.data.has_messages(s["username"])
            if only and not has:
                continue
            rows.append((has, s))
        self.table.setRowCount(len(rows))
        for i, (has, s) in enumerate(rows):
            import datetime
            t = (datetime.datetime.fromtimestamp(s["sort_time"]).strftime("%Y-%m-%d %H:%M")
                 if s["sort_time"] else "")
            cells = ["✔" if has else "", s["display"], s["username"], t, s["summary"]]
            for j, c in enumerate(cells):
                self.table.setItem(i, j, QTableWidgetItem(str(c)))
        self.log("会话列表：%d 个" % len(rows))

    def _selected_session(self):
        r = self.table.currentRow()
        if r < 0:
            return None
        item = self.table.item(r, 2)
        return item.text() if item else None

    def _show_preview(self):
        s = self._selected_session()
        if not s or self.data is None:
            return
        msgs = self.data.messages(s, limit=200)
        lines = ["%s（%d 条，显示最后 200 条）"
                 % (self.data.session_display(s), len(msgs)), "-" * 60]
        for m in msgs:
            who = "我" if m["is_sender"] else m["sender"]
            lines.append("[%s] %s: %s" % (m["time_str"], who,
                                          m["text"].replace("\n", " ⏎ ")))
        dlg = QMessageBox(self)
        dlg.setWindowTitle("会话预览")
        dlg.setText("\n".join(lines)[-8000:])
        dlg.exec_()

    # -- 导出 -------------------------------------------------------------
    def export(self, session=None):
        if self.data is None:
            QMessageBox.critical(self, "错误", "请先点『加载会话』")
            return
        self.btn_export.setEnabled(False)
        self.btn_export_one.setEnabled(False)
        acc = self.current_account()
        self._thread = ExportThread(self.edit_outdir.text(),
                                    self.edit_exportdir.text(),
                                    self.cmb_fmt.currentText(),
                                    acc["wxid"] if acc else "", session)
        self._thread.log.connect(self.log)
        self._thread.done.connect(self._export_done)
        self._thread.start()

    def export_selected(self):
        s = self._selected_session()
        if not s:
            QMessageBox.information(self, "提示", "请先在列表里选中一个会话")
            return
        self.export(session=s)

    def _export_done(self, ok, msg):
        self.btn_export.setEnabled(True)
        self.btn_export_one.setEnabled(True)
        if ok:
            QMessageBox.information(self, "导出完成", "%s\n目录：%s"
                                    % (msg, os.path.abspath(self.edit_exportdir.text())))
        else:
            QMessageBox.critical(self, "导出失败", msg)


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    w = Wx4ExportWindow()
    w.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
