import ctypes
import sys
import time
import traceback

from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import *

from app.DataBase import close_db
from app.log import logger
from app.ui import mainview
from app.ui.tool.pc_decrypt import pc_decrypt
from app.config import version
from wx4 import paths as wx4_paths
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WeChatReport")


class ViewController(QWidget):
    def __init__(self):
        super().__init__()
        self.viewMainWindow = None
        self.viewDecrypt = None
        self.viewWx4 = None

    def loadPCDecryptView(self):
        """
        登录界面（微信 3.x 流程）
        :return:
        """
        self.viewDecrypt = pc_decrypt.DecryptControl()
        self.viewDecrypt.DecryptSignal.connect(self.show_success)
        self.viewDecrypt.show()

    def loadWx4View(self):
        """
        微信 4.x 导出界面：检测微信 -> 取密钥 -> 解密 -> 导出
        :return:
        """
        from wx4.gui import Wx4ExportWindow
        self.viewWx4 = Wx4ExportWindow()
        self.viewWx4.show()

    def loadMainWinView(self, username=None):
        """
        聊天界面
        :param username: 账号
        :return:
        """
        username = ''
        start = time.time()
        self.viewMainWindow = mainview.MainWinController(username=username)
        self.viewMainWindow.exitSignal.connect(self.close)
        try:
            self.viewMainWindow.setWindowTitle(f"留痕-{version}")
            self.viewMainWindow.show()
            end = time.time()
            print('ok', '本次加载用了', end - start, 's')
            self.viewMainWindow.init_ui()
        except Exception as e:
            print(f"Exception: {e}")
            logger.error(traceback.print_exc())

    def show_success(self):
        QMessageBox.about(self, "解密成功", "数据库文件存储在\napp/DataBase/Msg\n文件夹下")

    def close(self) -> bool:
        close_db()
        super().close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    font = QFont('微软雅黑', 12)  # 使用 Times New Roman 字体，字体大小为 14
    app.setFont(font)
    view = ViewController()

    # 自动判断微信版本：4.x 用新的导出界面，3.x 用老的解密界面。
    wx4_accounts = []
    try:
        wx4_accounts = wx4_paths.list_account_dirs()
    except Exception:
        logger.error(traceback.format_exc())

    try:
        if wx4_accounts:
            print(f"检测到微信 4.x 数据目录 {len(wx4_accounts)} 个，使用 4.x 导出界面")
            view.loadWx4View()
        else:
            print("未检测到微信 4.x 数据目录，使用 3.x 解密界面")
            view.loadPCDecryptView()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Exception: {e}")
        logger.error(traceback.format_exc())
