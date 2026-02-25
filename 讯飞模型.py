import sys
import json
import base64
import hashlib
import hmac
import uuid
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode

import websocket
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QComboBox,
                             QTextBrowser, QTextEdit, QPushButton, QMessageBox,
                             QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
                             QFormLayout, QMenu, QInputDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt5.QtGui import QFont, QTextCursor
import markdown2
import html
from PyQt5.QtWidgets import QTabWidget

# ---------- 全局设置管理 ----------
class Settings:
    def __init__(self):
        self.qsettings = QSettings("XunFeiSpark", "ChatClient")
        self.app_id = self.qsettings.value("app_id", "")
        self.api_key = self.qsettings.value("api_key", "")
        self.api_secret = self.qsettings.value("api_secret", "")
        self.temperature = float(self.qsettings.value("temperature", 0.5))
        self.max_tokens = int(self.qsettings.value("max_tokens", 2048))
        # 读取自定义模型列表（存储为 JSON 字符串）
        custom_models_str = self.qsettings.value("custom_models", "[]")
        if isinstance(custom_models_str, str):
            import json
            self.custom_models = json.loads(custom_models_str)
        else:
            self.custom_models = []
    def save(self):
        self.qsettings.setValue("app_id", self.app_id)
        self.qsettings.setValue("api_key", self.api_key)
        self.qsettings.setValue("api_secret", self.api_secret)
        self.qsettings.setValue("temperature", self.temperature)
        self.qsettings.setValue("max_tokens", self.max_tokens)
        import json
        self.qsettings.setValue("custom_models", json.dumps(self.custom_models, ensure_ascii=False))


# ---------- 讯飞星火 API 客户端 ----------
class XunFeiSparkClient:
    MODEL_CONFIG = {
        "Spark Lite": {
            "url": "wss://spark-api.xf-yun.com/v1.1/chat",
            "domain": "lite"
        },
        "Spark X1.5": {
            "url": "wss://spark-api.xf-yun.com/v1/x1",
            "domain": "spark-x"
        },
        "Spark X2": {
            "url": "wss://spark-api.xf-yun.com/x2",
            "domain": "spark-x"
        },
        "Spark Pro": {
            "url":"wss://spark-api.xf-yun.com/v3.1/chat",
            "domain":"generalv3"
        },
        "Kimi K2.5": {
            "url":"wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat",
            "domain":"xopkimik25"
        },
        "MiniMax 2.5": {
            "url":"wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat",
            "domain":"xminimaxm25"
        },
        "Qwen3-1.7B": {
            "url":"wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat",
            "domain":"xop3qwen1b7"
        },
        "GLM-5": {
            "url":"wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat",
            "domain":"xopglm5"
        },
        "Hunyuan-MT-7B": {
            "url":"wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat",
            "domain":"xophunyuan7bmt"
        }
    }

    def __init__(self, app_id, api_key, api_secret, model_version):
        self.app_id = app_id
        self.api_key = api_key
        self.api_secret = api_secret
        self.model_version = model_version
        config = self.MODEL_CONFIG.get(model_version)
        if not config:
            raise ValueError(f"不支持的模型版本: {model_version}")
        self.base_url = config["url"]
        self.domain = config["domain"]

    def _build_auth_url(self):
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        path = parsed.path if parsed.path else '/'

        now = datetime.now(timezone.utc)
        date = now.strftime('%a, %d %b %Y %H:%M:%S GMT')

        signature_origin = f"host: {host}\n"
        signature_origin += f"date: {date}\n"
        signature_origin += f"GET {path} HTTP/1.1"

        signature_sha = hmac.new(
            self.api_secret.encode('utf-8'),
            signature_origin.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature = base64.b64encode(signature_sha).decode('utf-8')

        authorization_origin = (
            f'api_key="{self.api_key}", '
            f'algorithm="hmac-sha256", '
            f'headers="host date request-line", '
            f'signature="{signature}"'
        )
        authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode('utf-8')

        params = {
            "authorization": authorization,
            "date": date,
            "host": host
        }
        query_string = urlencode(params)
        return f"{self.base_url}?{query_string}"

    def send_message(self, messages, user_input, temperature=None, max_tokens=None, stop_check=None):
        """
        发送消息
        :param messages: 历史消息列表，格式 [{"role":"user/assistant","content":"..."}]
        :param user_input: 当前用户输入 (如果已包含在 messages 中可传空字符串)
        :param temperature: 可选，覆盖默认温度
        :param max_tokens: 可选，覆盖默认最大token数
        :return: (回复内容, 错误信息) 成功时错误信息为None
        """
        # 构建完整消息列表
        full_messages = messages.copy()
        if user_input:
            full_messages.append({"role": "user", "content": user_input})

        request_json = {
            "header": {"app_id": self.app_id},
            "parameter": {
                "chat": {
                    "domain": self.domain,
                    "temperature": temperature if temperature is not None else 0.5,
                    "max_tokens": max_tokens if max_tokens is not None else 2048,
                    "top_k": 4
                }
            },
            "payload": {"message": {"text": full_messages}}
        }

        ws_url = self._build_auth_url()
        try:
            ws = websocket.create_connection(ws_url, timeout=30)
            ws.send(json.dumps(request_json))

            full_content = ""
            sid = None
            usage = None
            while True:
                # 检查是否被请求停止
                if stop_check and stop_check():
                    ws.close()
                    return None, None, "用户取消了请求"
                response = ws.recv()
                if not response:
                    break
                resp_data = json.loads(response)
                header = resp_data.get("header", {})
                if not sid:
                    sid = header.get("sid")

                if header.get("code") != 0:
                    error_msg = header.get("message", "未知错误")
                    ws.close()
                    return None, None, f"API 错误 (sid: {sid}): {error_msg}"  # 返回三个值

                choices = resp_data.get("payload", {}).get("choices", {})
                if choices:
                    text_list = choices.get("text", [])
                    for item in text_list:
                        full_content += item.get("content", "")

                if header.get("status") == 2:  # 最后一次响应
                    if "payload" in resp_data and "usage" in resp_data["payload"]:
                        usage = resp_data["payload"]["usage"]  # 提取 usage
                    break
            ws.close()
            return full_content, usage, None
        except Exception as e:
            return None, None, f"网络或连接错误: {str(e)}"


import os

# ---------- 对话数据模型 ----------
class Conversation:
    def __init__(self, name, model_version, messages=None, conv_id=None, created_at=None):
        self.id = conv_id if conv_id else str(uuid.uuid4())[:8]
        self.name = name
        self.model_version = model_version
        self.messages = messages if messages is not None else []
        self.created_at = created_at if created_at is not None else time.time()

    def add_message(self, role, content):
        self.messages.append({"role": role, "content": content})
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "model_version": self.model_version,
            "messages": self.messages,
            "created_at": self.created_at
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            name=data.get("name", "未命名对话"),
            model_version=data.get("model_version", "Spark Lite"),
            messages=data.get("messages", []),
            conv_id=data.get("id"),
            created_at=data.get("created_at", time.time())  # 兼容旧文件
        )
class EditModelDialog(QDialog):
    def __init__(self, parent=None, name="", url="", domain=""):
        super().__init__(parent)
        self.setWindowTitle("编辑模型")
        self.setModal(True)
        self.resize(400, 200)

        layout = QFormLayout(self)

        self.name_edit = QLineEdit(name)
        self.url_edit = QLineEdit(url)
        self.domain_edit = QLineEdit(domain)

        layout.addRow("模型名称:", self.name_edit)
        layout.addRow("URL:", self.url_edit)
        layout.addRow("Domain:", self.domain_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_data(self):
        return self.name_edit.text().strip(), self.url_edit.text().strip(), self.domain_edit.text().strip()

# ---------- 设置对话框 ----------
class SettingsDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("设置")
        self.setModal(True)
        self.resize(500, 450)  # 高度略增以容纳新按钮

        main_layout = QVBoxLayout(self)

        # 创建标签页
        tab_widget = QTabWidget()

        # ---------- 第一页：基础参数 ----------
        basic_tab = QWidget()
        basic_layout = QFormLayout(basic_tab)

        self.app_id_edit = QLineEdit(settings.app_id)
        self.api_key_edit = QLineEdit(settings.api_key)
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_secret_edit = QLineEdit(settings.api_secret)
        self.api_secret_edit.setEchoMode(QLineEdit.Password)
        self.temp_edit = QLineEdit(str(settings.temperature))
        self.tokens_edit = QLineEdit(str(settings.max_tokens))

        basic_layout.addRow("APP ID:", self.app_id_edit)
        basic_layout.addRow("API Key:", self.api_key_edit)
        basic_layout.addRow("API Secret:", self.api_secret_edit)
        basic_layout.addRow("Temperature (0-1):", self.temp_edit)
        basic_layout.addRow("Max Tokens:", self.tokens_edit)

        tip_label = QLabel(
            '<a href="https://console.xfyun.cn/app/myapp" style="color:#0984e3; text-decoration:none;">'
            '本程序基于讯飞API构建，请进入讯飞云控制台进行API调用的申请、购买和使用。创建一个应用，获取APP ID、API Key和API Secret并填至上方。(部分模型请至https://maas.xfyun.cn/modelSquare查看）</a>'
        )
        tip_label.setOpenExternalLinks(True)
        tip_label.setAlignment(Qt.AlignCenter)
        tip_label.setWordWrap(True)
        tip_label.setStyleSheet("font-size: 13px; margin-top: 10px;")
        basic_layout.addRow(tip_label)

        tab_widget.addTab(basic_tab, "基础参数")

        # ---------- 第二页：自定义模型 ----------
        model_tab = QWidget()
        model_layout = QVBoxLayout(model_tab)

        # 模型列表
        self.model_list = QListWidget()
        self.model_list.setSelectionMode(QListWidget.SingleSelection)
        model_layout.addWidget(self.model_list)

        # 编辑按钮布局（添加/编辑/删除）
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("添加")
        self.edit_btn = QPushButton("编辑")
        self.delete_btn = QPushButton("删除")
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addStretch()
        model_layout.addLayout(btn_layout)

        # 导入/导出按钮布局
        import_export_layout = QHBoxLayout()
        self.import_btn = QPushButton("导入配置")
        self.export_btn = QPushButton("导出配置")
        import_export_layout.addWidget(self.import_btn)
        import_export_layout.addWidget(self.export_btn)
        import_export_layout.addStretch()
        model_layout.addLayout(import_export_layout)

        tab_widget.addTab(model_tab, "自定义模型")

        main_layout.addWidget(tab_widget)

        # 确定/取消按钮
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

        # 初始化模型列表
        self.refresh_model_list()

        # 连接信号
        self.add_btn.clicked.connect(self.add_model)
        self.edit_btn.clicked.connect(self.edit_model)
        self.delete_btn.clicked.connect(self.delete_model)
        self.import_btn.clicked.connect(self.import_models)
        self.export_btn.clicked.connect(self.export_models)
        self.model_list.itemDoubleClicked.connect(self.edit_model)

    def refresh_model_list(self):
        self.model_list.clear()
        for model in self.settings.custom_models:
            item = QListWidgetItem(f"{model['name']} - {model['url']} (domain: {model['domain']})")
            item.setData(Qt.UserRole, model)
            self.model_list.addItem(item)

    def add_model(self):
        dlg = EditModelDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            name, url, domain = dlg.get_data()
            if not name or not url or not domain:
                QMessageBox.warning(self, "输入错误", "所有字段都不能为空")
                return
            if any(m['name'] == name for m in self.settings.custom_models):
                QMessageBox.warning(self, "添加失败", f"模型名称 '{name}' 已存在")
                return
            self.settings.custom_models.append({"name": name, "url": url, "domain": domain})
            self.refresh_model_list()

    def edit_model(self):
        current = self.model_list.currentItem()
        if not current:
            QMessageBox.information(self, "提示", "请先选择一个模型")
            return
        model_data = current.data(Qt.UserRole)
        dlg = EditModelDialog(self, model_data['name'], model_data['url'], model_data['domain'])
        if dlg.exec_() == QDialog.Accepted:
            new_name, new_url, new_domain = dlg.get_data()
            if not new_name or not new_url or not new_domain:
                QMessageBox.warning(self, "输入错误", "所有字段都不能为空")
                return
            # 检查新名称是否与其他模型重复（不包括自身）
            if any(m['name'] == new_name for m in self.settings.custom_models if m['name'] != model_data['name']):
                QMessageBox.warning(self, "修改失败", f"模型名称 '{new_name}' 已存在")
                return
            # 更新数据
            model_data['name'] = new_name
            model_data['url'] = new_url
            model_data['domain'] = new_domain
            self.refresh_model_list()

    def delete_model(self):
        current = self.model_list.currentItem()
        if not current:
            QMessageBox.information(self, "提示", "请先选择一个模型")
            return
        model_data = current.data(Qt.UserRole)
        reply = QMessageBox.question(self, "确认删除", f"确定要删除模型 '{model_data['name']}' 吗？",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.settings.custom_models.remove(model_data)
            self.refresh_model_list()

    def import_models(self):
        from PyQt5.QtWidgets import QFileDialog
        import json
        file_path, _ = QFileDialog.getOpenFileName(self, "导入自定义模型配置", "", "JSON文件 (*.json)")
        if not file_path:
            return
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                imported = json.load(f)
            if not isinstance(imported, list):
                QMessageBox.warning(self, "导入失败", "文件格式错误：根元素应为列表")
                return
            # 合并导入的模型
            for model in imported:
                if not all(k in model for k in ('name', 'url', 'domain')):
                    continue  # 跳过格式不正确的项
                existing = next((m for m in self.settings.custom_models if m['name'] == model['name']), None)
                if existing:
                    reply = QMessageBox.question(self, "模型已存在",
                                                 f"模型名称 '{model['name']}' 已存在，是否覆盖？\n(选否则跳过此项)",
                                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if reply == QMessageBox.Yes:
                        existing['url'] = model['url']
                        existing['domain'] = model['domain']
                else:
                    self.settings.custom_models.append(model)
            self.refresh_model_list()
            QMessageBox.information(self, "导入完成", "自定义模型配置已导入。")
        except Exception as e:
            QMessageBox.critical(self, "导入错误", f"导入失败：{str(e)}")

    def export_models(self):
        from PyQt5.QtWidgets import QFileDialog
        import json
        if not self.settings.custom_models:
            QMessageBox.information(self, "导出", "没有自定义模型可导出。")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "导出自定义模型配置", "custom_models.json", "JSON文件 (*.json)")
        if not file_path:
            return
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings.custom_models, f, ensure_ascii=False, indent=2)
            QMessageBox.information(self, "导出成功", f"已导出 {len(self.settings.custom_models)} 个模型配置。")
        except Exception as e:
            QMessageBox.critical(self, "导出错误", f"导出失败：{str(e)}")

    def accept(self):
        try:
            # 保存基础参数
            self.settings.app_id = self.app_id_edit.text().strip()
            self.settings.api_key = self.api_key_edit.text().strip()
            self.settings.api_secret = self.api_secret_edit.text().strip()
            self.settings.temperature = float(self.temp_edit.text())
            self.settings.max_tokens = int(self.tokens_edit.text())
            # 自定义模型已在列表中直接修改了 self.settings.custom_models，无需再次赋值
            self.settings.save()
            super().accept()
        except ValueError as e:
            QMessageBox.warning(self, "输入错误", f"数字格式错误: {e}")
class ChatWorker(QThread):
    finished = pyqtSignal(str, object)  # (reply, usage)
    error = pyqtSignal(str)

    def __init__(self, client, messages, user_input, temperature, max_tokens):
        super().__init__()
        self.client = client
        self.messages = messages
        self.user_input = user_input
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._stop_requested = False  # 停止标志

    def stop(self):
        """请求线程停止"""
        self._stop_requested = True

    def run(self):
        # 定义一个检查函数，传递给客户端
        def should_stop():
            return self._stop_requested

        reply, usage, err = self.client.send_message(
            self.messages, self.user_input,
            temperature=self.temperature, max_tokens=self.max_tokens,
            stop_check=should_stop  # 传递检查函数
        )
        if err:
            self.error.emit(err)
        else:
            self.finished.emit(reply, usage)
# ---------- 主窗口 ----------
# ---------- 主窗口 ----------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = Settings()
        self.conversations = []
        self.current_conv_index = -1
        self.active_requests = {}  # 键: conv.id, 值: {"worker": worker, "start_time": time.time(), "model": model_version, "conv_name": conv.name}
        self.history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chat_history.json")
        self.last_send_time = 0  # 记录最后一次发送消息的时间（备用）
        self.init_ui()
        self.load_history()
        self.refresh_model_combo()
        # 不再自动创建默认对话，让用户通过设置后自动创建
        pass

    def update_new_btn_state(self):
        """根据对话列表是否为空，设置新建按钮的启用状态"""
        has_convs = len(self.conversations) > 0
        self.new_btn.setEnabled(has_convs)

    def init_ui(self):
        self.setWindowTitle("讯飞星火对话客户端")
        self.setGeometry(100, 100, 1100, 700)

        # 全局样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
            }
            QListWidget {
                background-color: #ffffff;
                color: #2f3640;
                border: none;
                border-right: 1px solid #dcdde1;
                font-size: 16px;
                outline: none;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #f1f2f6;
                margin: 5px;
                border-radius: 5px;
            }
            QListWidget::item:selected {
                background-color: #e1f5fe;
                color: #0984e3;
                font-weight: bold;
            }
            QListWidget::item:hover {
                background-color: #f1f2f6;
            }
            QPushButton {
                background-color: #0984e3;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 15px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #74b9ff;
            }
            QPushButton:pressed {
                background-color: #0984e3;
            }
            QPushButton:disabled {
                background-color: #b2bec3;
            }
            QTextBrowser {
                background-color: #ffffff;
                border: none;
                border-radius: 0;
                padding: 20px;
                font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
                font-size: 16px;
                selection-background-color: #74b9ff;
            }
            QTextEdit {
                background-color: #ffffff;
                border: 1px solid #dcdde1;
                border-radius: 8px;
                padding: 10px;
                font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
                font-size: 16px;
            }
            QTextEdit:focus {
                border: 1px solid #0984e3;
            }
            QTextBrowser pre {
                background-color: #2f3640;
                color: #f5f6fa;
                border-radius: 6px;
                padding: 12px;
                font-family: 'Consolas', 'Monaco', monospace;
                white-space: pre-wrap;
                margin: 10px 0;
            }
            QTextBrowser code {
                background-color: #dfe6e9;
                color: #c0392b;
                border-radius: 3px;
                padding: 2px 5px;
                font-family: 'Consolas', 'Monaco', monospace;
            }
            QComboBox {
                padding: 6px;
                border: 1px solid #dcdde1;
                border-radius: 6px;
                background: white;
                min-width: 150px;
                color: #2f3640;
                font-size: 16px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QLabel {
                color: #2f3640;
                font-size: 16px;
            }
        """)

        # 中央控件
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ========== 左侧侧栏 ==========
        left_panel = QWidget()
        left_panel.setFixedWidth(300)
        left_panel.setStyleSheet("background-color: #ffffff; border-right: 1px solid #dcdde1;")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        new_btn_container = QWidget()
        new_btn_layout = QVBoxLayout(new_btn_container)
        self.new_btn = QPushButton("➕ 新建对话")
        self.new_btn.setFixedHeight(60)
        self.new_btn.setStyleSheet("""
            QPushButton {
                background-color: #00b894;
                font-size: 16px;
                margin: 10px 10px 0 10px;
            }
            QPushButton:hover {
                background-color: #55efc4;
            }
        """)
        self.new_btn.clicked.connect(self.new_conversation)
        new_btn_layout.addWidget(self.new_btn)
        left_layout.addWidget(new_btn_container)

        self.conv_list = QListWidget()
        self.conv_list.setFrameShape(QListWidget.NoFrame)
        self.conv_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.conv_list.customContextMenuRequested.connect(self.show_context_menu)
        self.conv_list.itemClicked.connect(self.on_conversation_selected)
        left_layout.addWidget(self.conv_list)

        # ========== 左侧侧栏底部按钮容器 ==========
        bottom_buttons_widget = QWidget()
        bottom_buttons_layout = QVBoxLayout(bottom_buttons_widget)
        bottom_buttons_layout.setContentsMargins(10, 0, 10, 10)  # 左右边距10px，底部10px
        bottom_buttons_layout.setSpacing(5)  # 按钮间距5px

        # 活动请求按钮
        self.activity_btn = QPushButton("📊 活动请求")
        self.activity_btn.setFixedHeight(60)
        self.activity_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #636e72;
                border: 1px solid #dfe6e9;
                border-radius: 6px;
                font-size: 15px;
                font-weight: 600;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #f1f2f6;
                color: #2d3436;
            }
        """)
        self.activity_btn.clicked.connect(self.show_active_requests)
        bottom_buttons_layout.addWidget(self.activity_btn)

        # 设置按钮
        settings_btn = QPushButton("⚙️ 设置")
        settings_btn.setFixedHeight(60)
        settings_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #636e72;
                border: 1px solid #dfe6e9;
                border-radius: 6px;
                font-size: 15px;
                font-weight: 600;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #f1f2f6;
                color: #2d3436;
            }
        """)
        settings_btn.clicked.connect(self.open_settings)
        bottom_buttons_layout.addWidget(settings_btn)

        left_layout.addWidget(bottom_buttons_widget)

        main_layout.addWidget(left_panel)

        # ========== 右侧聊天区域 ==========
        right_panel = QWidget()
        right_panel.setStyleSheet("background-color: #f5f6fa;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(20, 20, 20, 20)
        right_layout.setSpacing(15)

        # 顶部工具栏
        top_bar = QWidget()
        top_bar.setStyleSheet("background-color: white; border-radius: 8px; padding: 10px;")
        top_bar_layout = QHBoxLayout(top_bar)
        top_bar_layout.setContentsMargins(10, 5, 10, 5)

        self.conv_name_label = QLabel("当前对话")
        self.conv_name_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #2f3640; border: none;")
        top_bar_layout.addWidget(self.conv_name_label)
        top_bar_layout.addStretch()
        
        model_label = QLabel("选择模型")
        model_label.setStyleSheet("color: #636e72; font-weight: 500; border: none;")
        top_bar_layout.addWidget(model_label)
        
        self.model_combo = QComboBox()
        self.model_combo.addItems(["Spark Lite", "Spark X1.5", "Spark X2", "Spark Pro", "Kimi K2.5", "MiniMax 2.5", "Qwen3-1.7B", "GLM-5", "Hunyuan-MT-7B"]) # 选择模型列表
        self.model_combo.currentTextChanged.connect(self.on_model_changed)
        top_bar_layout.addWidget(self.model_combo)

        right_layout.addWidget(top_bar)

        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(False)
        # 移除默认边框，使用样式表控制
        self.chat_display.setFrameShape(QTextBrowser.NoFrame)
        right_layout.addWidget(self.chat_display, 1)

        input_widget = QWidget()
        input_widget.setStyleSheet("background-color: white; border-radius: 8px; padding: 10px;")
        input_layout = QVBoxLayout(input_widget)
        input_layout.setContentsMargins(10, 10, 10, 10)

        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("输入消息... (Enter 发送, Ctrl+Enter 换行)")
        self.input_edit.setMaximumHeight(100)
        self.input_edit.setFrameShape(QTextEdit.NoFrame)
        input_layout.addWidget(self.input_edit)

        self.status_label = QLabel("AI 思考中，请稍候...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #7f8c8d; font-size: 12px; padding: 2px;")
        self.status_label.setVisible(False)  # 初始隐藏
        input_layout.addWidget(self.status_label)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.send_btn = QPushButton("发送")
        self.send_btn.setFixedWidth(100)
        self.send_btn.setCursor(Qt.PointingHandCursor)
        self.send_btn.clicked.connect(self.send_message)
        btn_layout.addWidget(self.send_btn)
        input_layout.addLayout(btn_layout)

        right_layout.addWidget(input_widget)

        main_layout.addWidget(right_panel, 1)

        self.input_edit.installEventFilter(self)
        self.update_ui_for_current_conv()

    def update_activity_button(self):
        """更新活动请求按钮文本"""
        count = len(self.active_requests)
        if count > 0:
            self.activity_btn.setText(f"📊 活动请求 ({count})")
        else:
            self.activity_btn.setText("📊 活动请求")

    def eventFilter(self, obj, event):
        if obj == self.input_edit and event.type() == event.KeyPress:
            if event.key() == Qt.Key_Return:
                if event.modifiers() == Qt.ControlModifier:
                    # Ctrl+Enter 插入换行
                    self.input_edit.insertPlainText("\n")
                    return True
                else:
                    # 单独 Enter 发送
                    self.send_message()
                    return True
        return super().eventFilter(obj, event)

    def save_history(self):
        try:
            data = [conv.to_dict() for conv in self.conversations]
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存历史失败: {e}")

    def load_history(self):
        if not os.path.exists(self.history_file):
            return
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.conversations = [Conversation.from_dict(d) for d in data]
            self.refresh_conv_list()
            if self.conversations:
                self.switch_to_conversation(0)  # 默认选中最新对话
        except Exception as e:
            print(f"加载历史失败: {e}")
        self.update_new_btn_state()  # 加载后更新按钮状态

    def new_conversation(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        default_model = self.model_combo.currentText()
        name = f"{now} {default_model}"
        conv = Conversation(name, default_model)
        self.conversations.append(conv)
        self.refresh_conv_list()
        # 找到新对话的索引并切换
        for i, c in enumerate(self.conversations):
            if c.id == conv.id:
                self.switch_to_conversation(i)
                break
        self.save_history()

    def show_context_menu(self, pos):
        item = self.conv_list.itemAt(pos)
        if not item:
            return

        menu = QMenu(self)
        rename_action = menu.addAction("重命名")
        delete_action = menu.addAction("删除")

        action = menu.exec_(self.conv_list.mapToGlobal(pos))
        
        if action == rename_action:
            self.rename_conversation(item)
        elif action == delete_action:
            self.delete_conversation(item)

    def rename_conversation(self, item):
        conv_id = item.data(Qt.UserRole)
        conv = next((c for c in self.conversations if c.id == conv_id), None)
        if not conv:
            return

        new_name, ok = QInputDialog.getText(self, "重命名对话", "请输入新名称:", text=conv.name)
        if ok and new_name.strip():
            conv.name = new_name.strip()
            item.setText(conv.name)
            if self.current_conv_index >= 0 and self.conversations[self.current_conv_index].id == conv_id:
                self.conv_name_label.setText(conv.name)
            self.save_history()

    def delete_conversation(self, item):
        conv_id = item.data(Qt.UserRole)
        # 如果该对话有活跃请求，进行安全停止
        if conv_id in self.active_requests:
            req_info = self.active_requests[conv_id]
            worker = req_info["worker"]
            # 断开信号连接，防止完成时操作已删除的对话
            try:
                worker.finished.disconnect()
                worker.error.disconnect()
            except:
                pass
            # 请求线程停止
            worker.stop()
            # 从活跃请求中移除，避免影响按钮状态
            del self.active_requests[conv_id]
            self.update_activity_button()
            # 更新当前会话控件状态（如果当前会话是该会话）
            if self.current_conv_index >= 0 and self.conversations[self.current_conv_index].id == conv_id:
                self.update_ui_for_current_conv()
            # 等待线程结束（最多2秒）
            if worker.isRunning():
                worker.wait(2000)

        # 确认删除
        reply = QMessageBox.question(self, "确认删除", "确定要删除这个对话吗？", 
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.conversations = [c for c in self.conversations if c.id != conv_id]
            self.refresh_conv_list()

            if not self.conversations:
                self.current_conv_index = -1
                self.chat_display.clear()
                self.conv_name_label.setText("无对话")
                self.update_ui_for_current_conv()
            else:
                self.switch_to_conversation(0)

            self.save_history()

    def on_conversation_selected(self, item):
        conv_id = item.data(Qt.UserRole)
        for i, conv in enumerate(self.conversations):
            if conv.id == conv_id:
                self.switch_to_conversation(i)
                break

    def switch_to_conversation(self, index):
        if index < 0 or index >= len(self.conversations):
            return
        self.current_conv_index = index
        conv = self.conversations[index]
        self.conv_name_label.setText(conv.name)
        self.model_combo.blockSignals(True)
        self.model_combo.setCurrentText(conv.model_version)
        self.model_combo.blockSignals(False)
        self.load_conversation_history(conv)
        self.update_ui_for_current_conv()
        self.status_label.setVisible(False)  # 切换对话时隐藏等待提示
        self.conv_list.setCurrentRow(index)

    def load_conversation_history(self, conv):
        self.chat_display.clear()
        for msg in conv.messages:
            self.append_message(msg["role"], msg["content"])

    def append_message(self, role, content, usage=None, elapsed=None, model_name=None):
        """将一条消息插入聊天显示区域，支持Markdown渲染和tokens显示，并通过段落格式强制消息间间距"""
        if role == "user":
            content_html = html.escape(content).replace('\\n', '<br>')
            full_html = f"""
            <div style='width: 100%; display: flex; justify-content: flex-start; margin-bottom: 0px;'>
                <div style='background-color: #e1f5fe; padding: 12px 16px 24px 16px; border-radius: 12px 12px 12px 0; max-width: 80%; font-size: 16px;'>
                    <div style='font-weight: bold; color: #0984e3; margin-bottom: 5px; text-align: left;'>你</div>
                    <div style='clear: both;'>{content_html}</div>
                </div>
            </div>
            """
        else:  # assistant
            content_html = markdown2.markdown(
                content,
                extras=[
                    'fenced-code-blocks',
                    'break-on-newline',
                    'tables',
                    'header-ids',
                    'cuddled-lists'
                ]
            )
            tokens_html = ""
            if usage and "text" in usage:
                u = usage["text"]
                total = u.get("total_tokens", 0)
                prompt = u.get("prompt_tokens", 0)
                completion = u.get("completion_tokens", 0)
                tokens_html = f"""
                <div style='font-size: 12px; color: #7f8c8d; text-align: right; margin-top: 5px; border-top: 1px dashed #bdc3c7; padding-top: 3px;'>
                    ↑ tokens: 本次使用 {total} (prompt {prompt} + completion {completion})
                </div>
                """

            # 使用传入的 model_name，如果没有则回退到当前会话的模型名（但理论上不会发生）
            if model_name is None and self.current_conv_index >= 0:
                model_name = self.conversations[self.current_conv_index].model_version
            name_display = model_name if model_name else "模型"
            if elapsed is not None:
                name_display += f" (用时 {elapsed:.1f}s)"

            full_html = f"""
            <div style='width: 100%; display: flex; justify-content: flex-end; margin-bottom: 0px;'>
                <div style='background-color: #f1f2f6; padding: 12px 16px 24px 16px; border-radius: 12px 12px 0 12px; max-width: 80%; font-size: 16px;'>
                    <div style='font-weight: bold; color: #2ecc71; margin-bottom: 5px; text-align: right;'>{name_display}</div>
                    <div style='text-align: left;'>
                        {content_html}
                    </div>
                    {tokens_html}
                </div>
            </div>
            """

        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertHtml(full_html)

        # 插入一个空白段落，并设置其上边距，实现消息间的间距
        cursor.insertBlock()
        block_format = cursor.blockFormat()
        block_format.setTopMargin(40)
        cursor.setBlockFormat(block_format)
        cursor.insertText('')

        self.chat_display.setTextCursor(cursor)
        self.chat_display.ensureCursorVisible()

    def update_ui_for_current_conv(self):
        has_conv = self.current_conv_index >= 0
        credentials_ok = bool(self.settings.app_id and self.settings.api_key and self.settings.api_secret)
        # 检查当前会话是否有活跃请求
        sending_disabled = False
        if has_conv:
            conv_id = self.conversations[self.current_conv_index].id
            sending_disabled = conv_id in self.active_requests
        self.send_btn.setEnabled(has_conv and credentials_ok and not sending_disabled)
        self.model_combo.setEnabled(not sending_disabled)

    def on_model_changed(self, new_model):
        if self.current_conv_index >= 0:
            self.conversations[self.current_conv_index].model_version = new_model

    def send_message(self):
        if self.current_conv_index < 0:
            QMessageBox.warning(self, "警告", "没有选中的对话")
            return
        if not self.settings.app_id or not self.settings.api_key or not self.settings.api_secret:
            QMessageBox.warning(self, "警告", "请在设置中填写API凭证")
            return

        user_input = self.input_edit.toPlainText().strip()
        if not user_input:
            return

        conv = self.conversations[self.current_conv_index]

        # 将用户消息加入历史和显示
        conv.add_message("user", user_input)
        self.append_message("user", user_input)
        self.save_history()
        self.input_edit.clear()

        # 创建客户端
        try:
            client = XunFeiSparkClient(
                self.settings.app_id,
                self.settings.api_key,
                self.settings.api_secret,
                conv.model_version
            )
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建客户端失败: {e}")
            # 移除刚添加的用户消息
            conv.messages.pop()
            self.update_ui_for_current_conv()
            return

        # 启动工作线程
        self.worker = ChatWorker(
            client,
            conv.messages,  # 包含所有历史消息（包括刚添加的user）
            "",  # user_input 已经包含在 messages 中
            self.settings.temperature,
            self.settings.max_tokens
        )
        current_model = conv.model_version  # 记录发送时使用的模型
        self.worker.finished.connect(lambda reply, usage: self.on_reply_received(reply, usage, conv, current_model))
        self.worker.error.connect(lambda err: self.on_error(err, conv))
        self.last_send_time = time.time()  # 记录发送时刻
        # 加入活跃请求（使用 current_model）
        self.active_requests[conv.id] = {
            "worker": self.worker,
            "start_time": self.last_send_time,
            "model": current_model,
            "conv_name": conv.name
        }
        self.update_activity_button()
        # 禁用控件（此时 active_requests 已有该会话）
        self.update_ui_for_current_conv()
        self.worker.start()

    def on_reply_received(self, reply, usage, conv, model_used):
        # 从 active_requests 获取开始时间
        req_info = self.active_requests.get(conv.id)
        if req_info:
            elapsed = time.time() - req_info["start_time"]
        else:
            elapsed = 0
        conv.add_message("assistant", reply)
        self.append_message("assistant", reply, usage=usage, elapsed=elapsed, model_name=model_used)
        self.save_history()

        if conv.id in self.active_requests:
            del self.active_requests[conv.id]
            self.update_activity_button()
        # 如果当前会话是该会话，更新控件状态
        if self.current_conv_index >= 0 and self.conversations[self.current_conv_index].id == conv.id:
            self.update_ui_for_current_conv()

    def on_error(self, err_msg, conv):
        QMessageBox.critical(self, "错误", err_msg)
        # 移除之前添加的用户消息
        if conv.messages and conv.messages[-1]["role"] == "user":
            conv.messages.pop()
        if conv.id in self.active_requests:
            del self.active_requests[conv.id]
            self.update_activity_button()
        if self.current_conv_index >= 0 and self.conversations[self.current_conv_index].id == conv.id:
            self.update_ui_for_current_conv()

    def show_active_requests(self):
        if not self.active_requests:
            QMessageBox.information(self, "活动请求", "当前没有正在进行的请求。")
            return
        dlg = QDialog(self)
        dlg.setWindowTitle("活动请求")
        dlg.resize(400, 300)
        layout = QVBoxLayout(dlg)
        list_widget = QListWidget()
        for conv_id, info in self.active_requests.items():
            elapsed = time.time() - info["start_time"]
            item_text = f"会话: {info['conv_name']} | 模型: {info['model']} | 已耗时: {elapsed:.1f}s"
            list_widget.addItem(item_text)
        layout.addWidget(list_widget)
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)
        dlg.exec_()

    def open_settings(self):
        """打开设置对话框"""
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec_() == QDialog.Accepted:
            self.update_ui_for_current_conv()
            self.refresh_model_combo()
            # 如果对话列表为空，自动创建第一个对话
            if len(self.conversations) == 0:
                self.new_conversation()
            QMessageBox.information(self, "提示", "设置已保存。")

    def refresh_model_combo(self):
        """合并内置模型和自定义模型，更新下拉框和客户端配置"""
        # 内置模型（硬编码）
        builtin_models = {
            "Spark Lite": {"url": "wss://spark-api.xf-yun.com/v1.1/chat", "domain": "lite"},
            "Spark X1.5": {"url": "wss://spark-api.xf-yun.com/v1/x1", "domain": "spark-x"},
            "Spark X2": {"url": "wss://spark-api.xf-yun.com/x2", "domain": "spark-x"},
            "Spark Pro": {"url": "wss://spark-api.xf-yun.com/v3.1/chat", "domain": "generalv3"},
            "Kimi K2.5": {"url": "wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat", "domain": "xopkimik25"},
            "MiniMax 2.5": {"url": "wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat", "domain": "xminimaxm25"},
            "Qwen3-1.7B": {"url": "wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat", "domain": "xop3qwen1b7"},
            "GLM-5": {"url": "wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat", "domain": "xopglm5"},
            "Hunyuan-MT-7B": {"url": "wss://maas-api.cn-huabei-1.xf-yun.com/v1.1/chat", "domain": "xophunyuan7bmt"},
        }

        # 自定义模型
        custom_models = {}
        for m in self.settings.custom_models:
            custom_models[m['name']] = {"url": m['url'], "domain": m['domain']}

        # 合并，自定义模型会覆盖同名内置模型（如果需要）
        merged = builtin_models.copy()
        merged.update(custom_models)

        # 更新 XunFeiSparkClient 的类变量
        XunFeiSparkClient.MODEL_CONFIG = merged

        # 更新下拉框
        current_model = self.model_combo.currentText()
        self.model_combo.clear()
        self.model_combo.addItems(sorted(merged.keys()))

        # 如果当前对话使用的模型在新列表中，则选中它；否则选中第一个
        if self.current_conv_index >= 0:
            conv = self.conversations[self.current_conv_index]
            if conv.model_version in merged:
                self.model_combo.setCurrentText(conv.model_version)
            else:
                # 如果当前模型不存在（可能被删除了），切换到第一个
                if merged:
                    first_model = sorted(merged.keys())[0]
                    self.model_combo.setCurrentText(first_model)
                    conv.model_version = first_model
                    self.conv_name_label.setText(conv.name)  # 名称不变
        else:
            # 没有对话时，默认选中第一个
            if merged:
                self.model_combo.setCurrentIndex(0)

    def refresh_conv_list(self):
        """按创建时间降序排序对话列表，并重新填充左侧列表"""
        # 按 created_at 降序排序
        self.conversations.sort(key=lambda c: c.created_at, reverse=True)
        
        # 清空列表控件
        self.conv_list.clear()
        
        # 重新添加所有对话项
        for conv in self.conversations:
            item = QListWidgetItem(conv.name)
            item.setData(Qt.UserRole, conv.id)
            self.conv_list.addItem(item)
        
        # 如果当前有选中的对话，根据 ID 重新高亮它
        if self.current_conv_index >= 0 and self.current_conv_index < len(self.conversations):
            current_id = self.conversations[self.current_conv_index].id
            for i, conv in enumerate(self.conversations):
                if conv.id == current_id:
                    self.current_conv_index = i
                    self.conv_list.setCurrentRow(i)
                    break
        else:
            self.current_conv_index = -1
        self.update_new_btn_state()  # 更新按钮状态

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # 设置全局字体为微软雅黑
    font = QFont("Microsoft YaHei", 9)  # 9为默认字号，可自行调整
    app.setFont(font)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())