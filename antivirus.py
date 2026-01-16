import sys
import os
import ctypes
import json
import shutil
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit,
                             QProgressBar, QFileDialog, QHBoxLayout, QMessageBox, QTabWidget,
                             QGroupBox, QCheckBox, QLineEdit, QSpinBox, QComboBox, QTableWidget,
                             QTableWidgetItem, QHeaderView, QSplitter, QListWidget, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon

try:
    from PyQt5.QtChart import QChart, QChartView, QPieSeries
    HAS_CHART = True
except ImportError:
    HAS_CHART = False
    print("[경고] PyQtChart가 설치되지 않았습니다. 차트 기능이 비활성화됩니다.")
    print("       설치: pip install PyQtChart")

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ============================================================================
# 전역 설정
# ============================================================================
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.json")

def load_settings():
    """설정 파일 로드"""
    default_settings = {
        'quarantine_dir': os.path.join(os.path.dirname(__file__), "quarantine")
    }
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                settings = json.load(f)
                # 기본값과 병합
                for key, value in default_settings.items():
                    if key not in settings:
                        settings[key] = value
                return settings
        except:
            return default_settings
    return default_settings

def save_settings(settings):
    """설정 파일 저장"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"설정 저장 오류: {e}")
        return False

# 설정 로드
SETTINGS = load_settings()
QUARANTINE_DIR = SETTINGS['quarantine_dir']
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# ============================================================================
# DLL 로딩
# ============================================================================
if sys.platform.startswith("win"):
    dll_dir = os.path.dirname(os.path.abspath(__file__))
    os.environ["PATH"] = dll_dir + os.pathsep + os.environ["PATH"]
    try:
        os.add_dll_directory(dll_dir)
    except AttributeError:
        pass

if sys.platform.startswith("win"):
    libname = "antivirus_core.dll"
else:
    libname = "libantivirus_core.so"

try:
    engine = ctypes.CDLL(os.path.join(os.path.dirname(__file__), libname))
    engine.scan_file.argtypes = [ctypes.c_wchar_p]
    engine.scan_file.restype = ctypes.c_int

    has_detailed_scan = False
    has_add_signature = False
    has_add_hash = False

    try:
        engine.scan_file_detailed.argtypes = [ctypes.c_wchar_p]
        engine.scan_file_detailed.restype = ctypes.c_char_p
        has_detailed_scan = True
    except AttributeError:
        print("[경고] scan_file_detailed 함수를 찾을 수 없습니다.")

    try:
        engine.add_signature.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        engine.add_signature.restype = ctypes.c_int
        has_add_signature = True
    except AttributeError:
        print("[경고] add_signature 함수를 찾을 수 없습니다.")

    try:
        engine.add_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_bool]
        engine.add_hash.restype = ctypes.c_int
        has_add_hash = True
    except AttributeError:
        print("[경고] add_hash 함수를 찾을 수 없습니다.")

    print(f"[성공] {libname} 로드 완료!")
    print(f"  - 기본 스캔: ✓")
    print(f"  - 상세 스캔: {'✓' if has_detailed_scan else '✗'}")
    print(f"  - 시그니처 추가: {'✓' if has_add_signature else '✗'}")
    print(f"  - 해시 추가: {'✓' if has_add_hash else '✗'}")

except Exception as e:
    print(f"\n[치명적 오류] DLL 로드 실패: {e}\n")
    sys.exit(1)

# ============================================================================
# 스캔 통계 클래스
# ============================================================================
class ScanStats:
    def __init__(self):
        self.total_scanned = 0
        self.clean_files = 0
        self.malicious_files = 0
        self.suspicious_files = 0
        self.errors = 0
        self.quarantined = 0

    def reset(self):
        self.__init__()

# ============================================================================
# 스캔 함수
# ============================================================================
def scan_file_basic(filepath):
    result = engine.scan_file(filepath)
    status_map = {0: "정상", 1: "악성-시그니처", 2: "악성-해시", 3: "의심-휴리스틱", -1: "오류"}
    status_text = status_map.get(result, "알수없음")
    return f"[{status_text}] {filepath}", result

def scan_file_detailed(filepath):
    if not has_detailed_scan:
        msg, code = scan_file_basic(filepath)
        return {
            "status": code, "threat_type": "unknown", "threat_name": msg.split(']')[0].replace('[', ''),
            "md5": "", "sha256": "", "entropy": 0.0, "file_size": 0
        }
    try:
        result_json = engine.scan_file_detailed(filepath)
        return json.loads(result_json.decode('utf-8'))
    except Exception as e:
        print(f"상세 스캔 오류: {e}")
        msg, code = scan_file_basic(filepath)
        return {
            "status": code, "threat_type": "unknown", "threat_name": "Scan Error",
            "md5": "", "sha256": "", "entropy": 0.0, "file_size": 0
        }

# ============================================================================
# 배치 스캔 스레드
# ============================================================================
class BatchScanThread(QThread):
    progress = pyqtSignal(int)
    result_msg = pyqtSignal(str)
    result_detailed = pyqtSignal(dict)
    stats_update = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, file_list, use_detailed=True):
        super().__init__()
        self.file_list = file_list
        self.use_detailed = use_detailed
        self.stats = ScanStats()
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        for i, filepath in enumerate(self.file_list, 1):
            if self._stop_requested:
                self.result_msg.emit("\n[중지됨] 사용자가 스캔을 중지했습니다.\n")
                break

            if self.use_detailed:
                result_dict = scan_file_detailed(filepath)
                result_dict['filepath'] = filepath
                self.result_detailed.emit(result_dict)

                status = result_dict.get('status', -1)
                self.stats.total_scanned += 1
                if status == 0:
                    self.stats.clean_files += 1
                elif status in [1, 2]:
                    self.stats.malicious_files += 1
                elif status == 3:
                    self.stats.suspicious_files += 1
                else:
                    self.stats.errors += 1

                status_map = {0: "정상", 1: "악성-시그니처", 2: "악성-해시", 3: "의심-휴리스틱", -1: "오류"}
                status = status_map.get(result_dict.get('status', -1), "알수없음")
                threat = result_dict.get('threat_name', 'Unknown')
                msg = f"[{status}] {threat} - {os.path.basename(filepath)}"
                self.result_msg.emit(msg)
            else:
                msg, code = scan_file_basic(filepath)
                self.result_msg.emit(msg)
                self.stats.total_scanned += 1
                if code == 0:
                    self.stats.clean_files += 1
                elif code in [1, 2]:
                    self.stats.malicious_files += 1
                elif code == 3:
                    self.stats.suspicious_files += 1
                else:
                    self.stats.errors += 1

            self.stats_update.emit({
                'total': self.stats.total_scanned,
                'clean': self.stats.clean_files,
                'malicious': self.stats.malicious_files,
                'suspicious': self.stats.suspicious_files,
                'errors': self.stats.errors
            })
            self.progress.emit(i)

        self.finished.emit()

# ============================================================================
# 실시간 모니터링
# ============================================================================
class FolderHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            msg, _ = scan_file_basic(event.src_path)
            self.callback(msg)

# ============================================================================
# 메인 GUI
# ============================================================================
class AntivirusGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️ InfraRed")
        self.setGeometry(100, 50, 1400, 900)
        self.stats = ScanStats()
        self.scan_history = self.load_history()
        self.dark_mode = False
        self.init_ui()
        self.apply_theme()
        self.observer = None
        self.scan_thread = None

        # 실시간 통계 업데이트 타이머
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_dashboard)
        self.stats_timer.start(1000)

    def init_ui(self):
        main_layout = QVBoxLayout()

        # 상단 툴바
        toolbar = self.create_toolbar()
        main_layout.addWidget(toolbar)

        # 탭 위젯
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_dashboard_tab(), "📊 대시보드")
        self.tabs.addTab(self.create_scan_tab(), "🔍 파일 검사")
        self.tabs.addTab(self.create_quarantine_tab(), "🗂️ 격리 구역")
        self.tabs.addTab(self.create_monitor_tab(), "👁️ 실시간 감시")
        self.tabs.addTab(self.create_settings_tab(), "⚙️ 설정")
        self.tabs.addTab(self.create_history_tab(), "📜 히스토리")
        self.tabs.addTab(self.create_help_tab(), "❓ 도움말")
        main_layout.addWidget(self.tabs)

        # 하단 상태바
        self.status_label = QLabel("준비 완료")
        self.status_label.setStyleSheet("padding: 8px; background-color: #2c3e50; color: white; border-radius: 4px;")
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

    def create_toolbar(self):
        toolbar = QFrame()
        toolbar.setFrameShape(QFrame.StyledPanel)
        layout = QHBoxLayout()

        title = QLabel("🛡️ InfraRed")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)

        layout.addStretch()

        # 빠른 스캔 버튼
        quick_scan_btn = QPushButton("⚡ 빠른 스캔")
        quick_scan_btn.clicked.connect(self.quick_scan)
        quick_scan_btn.setStyleSheet("padding: 8px 16px; font-weight: bold;")
        layout.addWidget(quick_scan_btn)

        # 다크모드 토글
        self.theme_btn = QPushButton("🌙 다크모드")
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.theme_btn.setStyleSheet("padding: 8px 16px;")
        layout.addWidget(self.theme_btn)

        toolbar.setLayout(layout)
        return toolbar

    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 통계 카드
        stats_layout = QHBoxLayout()
        self.total_card = self.create_stat_card("총 스캔", "0", "#3498db")
        self.clean_card = self.create_stat_card("정상", "0", "#2ecc71")
        self.malicious_card = self.create_stat_card("악성", "0", "#e74c3c")
        self.suspicious_card = self.create_stat_card("의심", "0", "#f39c12")

        stats_layout.addWidget(self.total_card)
        stats_layout.addWidget(self.clean_card)
        stats_layout.addWidget(self.malicious_card)
        stats_layout.addWidget(self.suspicious_card)
        layout.addLayout(stats_layout)

        # 차트 및 위협 목록 영역
        chart_splitter = QSplitter(Qt.Horizontal)

        # 파이 차트 또는 대체 UI
        self.pie_chart_widget = self.create_pie_chart()
        chart_splitter.addWidget(self.pie_chart_widget)

        # 최근 위협 목록
        recent_threats_group = QGroupBox("🚨 최근 발견된 위협")
        recent_layout = QVBoxLayout()
        self.recent_threats_list = QListWidget()
        self.recent_threats_list.setMinimumHeight(200)
        recent_layout.addWidget(self.recent_threats_list)
        recent_threats_group.setLayout(recent_layout)
        chart_splitter.addWidget(recent_threats_group)

        # 차트와 위협 목록 비율 설정 (1:1)
        chart_splitter.setSizes([500, 500])
        chart_splitter.setMinimumHeight(300)
        layout.addWidget(chart_splitter)

        # 시스템 정보
        info_group = QGroupBox("ℹ️ 시스템 정보")
        info_layout = QVBoxLayout()
        self.system_info_label = QLabel()
        self.update_system_info()
        info_layout.addWidget(self.system_info_label)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        tab.setLayout(layout)
        return tab

    def create_stat_card(self, title, value, color):
        card = QFrame()
        card.setFrameShape(QFrame.StyledPanel)
        card.setStyleSheet(f"background-color: {color}; border-radius: 8px; padding: 20px;")
        card.setMinimumHeight(120)
        card.setMinimumWidth(150)

        layout = QVBoxLayout()
        title_label = QLabel(title)
        title_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)

        value_label = QLabel(value)
        value_label.setStyleSheet("color: white; font-size: 42px; font-weight: bold;")
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setObjectName(f"{title}_value")

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addStretch()
        card.setLayout(layout)
        return card

    def create_pie_chart(self):
        """파이 차트 생성 (PyQtChart 사용 가능 시) 또는 대체 UI"""
        if HAS_CHART:
            # PyQtChart 사용
            from PyQt5.QtChart import QPieSeries, QChart, QChartView
            from PyQt5.QtGui import QPainter

            self.pie_series = QPieSeries()
            self.pie_series.append("정상", max(self.stats.clean_files, 1))
            self.pie_series.append("악성", self.stats.malicious_files)
            self.pie_series.append("의심", self.stats.suspicious_files)

            # 슬라이스 색상 설정
            slice_clean = self.pie_series.slices()[0]
            slice_clean.setBrush(QColor("#2ecc71"))
            slice_clean.setLabelVisible(True)

            if len(self.pie_series.slices()) > 1:
                slice_malicious = self.pie_series.slices()[1]
                slice_malicious.setBrush(QColor("#e74c3c"))
                slice_malicious.setLabelVisible(True)

            if len(self.pie_series.slices()) > 2:
                slice_suspicious = self.pie_series.slices()[2]
                slice_suspicious.setBrush(QColor("#f39c12"))
                slice_suspicious.setLabelVisible(True)

            self.pie_chart = QChart()
            self.pie_chart.addSeries(self.pie_series)
            self.pie_chart.setTitle("📊 스캔 결과 분포")
            self.pie_chart.setAnimationOptions(QChart.SeriesAnimations)
            self.pie_chart.legend().setVisible(True)
            self.pie_chart.legend().setAlignment(Qt.AlignBottom)

            chart_view = QChartView(self.pie_chart)
            chart_view.setRenderHint(QPainter.Antialiasing)
            chart_view.setMinimumSize(400, 300)
            return chart_view
        else:
            # PyQtChart가 없을 때 대체 UI
            group = QGroupBox("📊 스캔 결과 분포")
            layout = QVBoxLayout()
            self.chart_text = QTextEdit()
            self.chart_text.setReadOnly(True)
            self.chart_text.setMaximumHeight(300)
            self.chart_text.setStyleSheet("""
                QTextEdit {
                    font-size: 14px;
                    font-family: 'Consolas', monospace;
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 10px;
                }
            """)
            self.update_chart_text()
            layout.addWidget(self.chart_text)
            group.setLayout(layout)
            return group

    def update_chart_text(self):
        """차트 텍스트 업데이트 (PyQtChart 없을 때)"""
        if not HAS_CHART and hasattr(self, 'chart_text'):
            total = self.stats.total_scanned
            if total == 0:
                total = 1  # 0으로 나누기 방지

            clean_pct = (self.stats.clean_files / total) * 100
            malicious_pct = (self.stats.malicious_files / total) * 100
            suspicious_pct = (self.stats.suspicious_files / total) * 100

            text = f"""
╔══════════════════════════════════════╗
║        스캔 결과 통계                ║
╚══════════════════════════════════════╝

✅ 정상 파일
   개수: {self.stats.clean_files}개
   비율: {clean_pct:.1f}%
   {'█' * int(clean_pct / 2)}

🔴 악성 파일
   개수: {self.stats.malicious_files}개
   비율: {malicious_pct:.1f}%
   {'█' * int(malicious_pct / 2)}

⚠️  의심 파일
   개수: {self.stats.suspicious_files}개
   비율: {suspicious_pct:.1f}%
   {'█' * int(suspicious_pct / 2)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
총 스캔: {self.stats.total_scanned}개
"""
            self.chart_text.setPlainText(text)

    def update_pie_chart(self):
        """파이 차트 업데이트"""
        if HAS_CHART and hasattr(self, 'pie_series'):
            # 기존 데이터 제거
            self.pie_series.clear()

            # 새 데이터 추가 (최소값 1로 설정하여 차트가 항상 표시되도록)
            clean = max(self.stats.clean_files, 0)
            malicious = max(self.stats.malicious_files, 0)
            suspicious = max(self.stats.suspicious_files, 0)

            # 모든 값이 0이면 기본값 표시
            if clean == 0 and malicious == 0 and suspicious == 0:
                clean = 1

            self.pie_series.append("정상", clean)
            self.pie_series.append("악성", malicious)
            self.pie_series.append("의심", suspicious)

            # 슬라이스 색상 및 레이블 설정
            if len(self.pie_series.slices()) > 0:
                slice_clean = self.pie_series.slices()[0]
                slice_clean.setBrush(QColor("#2ecc71"))
                slice_clean.setLabelVisible(True)
                slice_clean.setLabel(f"정상 ({clean})")

            if len(self.pie_series.slices()) > 1:
                slice_malicious = self.pie_series.slices()[1]
                slice_malicious.setBrush(QColor("#e74c3c"))
                slice_malicious.setLabelVisible(True)
                slice_malicious.setLabel(f"악성 ({malicious})")

            if len(self.pie_series.slices()) > 2:
                slice_suspicious = self.pie_series.slices()[2]
                slice_suspicious.setBrush(QColor("#f39c12"))
                slice_suspicious.setLabelVisible(True)
                slice_suspicious.setLabel(f"의심 ({suspicious})")
        else:
            # 텍스트 차트 업데이트
            self.update_chart_text()

    def create_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 스캔 옵션
        btn_group = QGroupBox("🔍 검사 옵션")
        btn_layout = QVBoxLayout()

        # 첫 번째 줄: 기본 스캔
        btn_row1 = QHBoxLayout()
        self.select_btn = QPushButton('📄 파일 선택')
        self.select_btn.clicked.connect(self.choose_and_scan)
        btn_row1.addWidget(self.select_btn)

        self.folder_btn = QPushButton('📁 폴더 검사')
        self.folder_btn.clicked.connect(self.scan_folder)
        btn_row1.addWidget(self.folder_btn)

        self.full_scan_btn = QPushButton('💻 전체 시스템 검사')
        self.full_scan_btn.clicked.connect(self.full_system_scan)
        btn_row1.addWidget(self.full_scan_btn)
        btn_layout.addLayout(btn_row1)

        # 두 번째 줄: 드라이브 및 USB 스캔
        btn_row2 = QHBoxLayout()
        self.drive_scan_btn = QPushButton('💿 드라이브 선택 검사')
        self.drive_scan_btn.clicked.connect(self.scan_drive)
        btn_row2.addWidget(self.drive_scan_btn)

        self.all_drives_btn = QPushButton('🖥️ 모든 드라이브 검사')
        self.all_drives_btn.clicked.connect(self.scan_all_drives)
        btn_row2.addWidget(self.all_drives_btn)

        self.usb_scan_btn = QPushButton('🔌 USB 검사')
        self.usb_scan_btn.clicked.connect(self.scan_usb)
        btn_row2.addWidget(self.usb_scan_btn)
        btn_layout.addLayout(btn_row2)

        # 옵션
        options_row = QHBoxLayout()
        self.detailed_check = QCheckBox("상세 스캔")
        self.detailed_check.setChecked(True)
        options_row.addWidget(self.detailed_check)

        self.auto_quarantine_check = QCheckBox("자동 격리")
        options_row.addWidget(self.auto_quarantine_check)

        self.recursive_check = QCheckBox("하위 폴더 포함")
        self.recursive_check.setChecked(True)
        options_row.addWidget(self.recursive_check)
        btn_layout.addLayout(options_row)

        btn_group.setLayout(btn_layout)
        layout.addWidget(btn_group)

        # 진행 상황
        progress_group = QGroupBox("📈 검사 진행")
        progress_layout = QVBoxLayout()
        self.progress = QProgressBar()
        progress_layout.addWidget(self.progress)

        self.progress_label = QLabel("대기 중...")
        progress_layout.addWidget(self.progress_label)

        # 중지 버튼
        self.stop_scan_btn = QPushButton('⏹️ 검사 중지')
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold;")
        progress_layout.addWidget(self.stop_scan_btn)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        # 결과 테이블
        result_group = QGroupBox("📋 검사 결과")
        result_layout = QVBoxLayout()

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(["파일명", "상태", "위협", "MD5", "크기", "작업"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        result_layout.addWidget(self.result_table)

        result_btn_layout = QHBoxLayout()
        clear_btn = QPushButton('🗑️ 결과 지우기')
        clear_btn.clicked.connect(lambda: self.result_table.setRowCount(0))
        result_btn_layout.addWidget(clear_btn)

        export_btn = QPushButton('💾 결과 내보내기')
        export_btn.clicked.connect(self.export_results)
        result_btn_layout.addWidget(export_btn)
        result_layout.addLayout(result_btn_layout)

        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        tab.setLayout(layout)
        return tab

    def create_quarantine_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        info_label = QLabel(f"📁 격리 폴더: {QUARANTINE_DIR}")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # 격리된 파일 목록
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["파일명", "격리 시간", "위협 유형", "작업"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.quarantine_table)

        # 버튼
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton('🔄 새로고침')
        refresh_btn.clicked.connect(self.refresh_quarantine)
        btn_layout.addWidget(refresh_btn)

        restore_btn = QPushButton('↩️ 복원')
        restore_btn.clicked.connect(self.restore_from_quarantine)
        btn_layout.addWidget(restore_btn)

        delete_btn = QPushButton('🗑️ 영구 삭제')
        delete_btn.clicked.connect(self.delete_from_quarantine)
        btn_layout.addWidget(delete_btn)

        clear_all_btn = QPushButton('🧹 전체 비우기')
        clear_all_btn.clicked.connect(self.clear_quarantine)
        btn_layout.addWidget(clear_all_btn)

        layout.addLayout(btn_layout)
        tab.setLayout(layout)
        self.refresh_quarantine()
        return tab

    def create_monitor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        control_group = QGroupBox("🎛️ 실시간 감시 제어")
        control_layout = QVBoxLayout()

        self.monitor_btn = QPushButton('▶️ 실시간 감시 시작')
        self.monitor_btn.setCheckable(True)
        self.monitor_btn.toggled.connect(self.toggle_monitoring)
        control_layout.addWidget(self.monitor_btn)

        self.monitor_path_label = QLabel("감시 중인 폴더: 없음")
        self.monitor_path_label.setWordWrap(True)
        control_layout.addWidget(self.monitor_path_label)

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

        # 감시 로그
        log_group = QGroupBox("📝 실시간 감시 로그")
        log_layout = QVBoxLayout()
        self.monitor_log = QTextEdit(readOnly=True)
        self.monitor_log.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.monitor_log)

        clear_log_btn = QPushButton('🗑️ 로그 지우기')
        clear_log_btn.clicked.connect(self.monitor_log.clear)
        log_layout.addWidget(clear_log_btn)

        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        tab.setLayout(layout)
        return tab

    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 격리 폴더 설정
        quarantine_group = QGroupBox("🛠️ 격리 폴더 설정")
        quarantine_layout = QVBoxLayout()

        # 현재 격리 폴더 표시
        current_folder_layout = QHBoxLayout()
        current_folder_layout.addWidget(QLabel("현재 격리 폴더:"))
        self.quarantine_path_label = QLabel(QUARANTINE_DIR)
        self.quarantine_path_label.setObjectName("quarantine_path_label")
        self.quarantine_path_label.setWordWrap(True)
        current_folder_layout.addWidget(self.quarantine_path_label)
        current_folder_layout.addStretch()
        quarantine_layout.addLayout(current_folder_layout)

        # 버튼
        quarantine_btn_layout = QHBoxLayout()
        change_folder_btn = QPushButton('📂 폴더 변경')
        change_folder_btn.clicked.connect(self.change_quarantine_folder)
        change_folder_btn.setStyleSheet("padding: 8px 16px;")
        quarantine_btn_layout.addWidget(change_folder_btn)

        open_folder_btn = QPushButton('🔍 폴더 열기')
        open_folder_btn.clicked.connect(self.open_quarantine_folder)
        open_folder_btn.setStyleSheet("padding: 8px 16px;")
        quarantine_btn_layout.addWidget(open_folder_btn)

        reset_folder_btn = QPushButton('🔄 기본값으로')
        reset_folder_btn.clicked.connect(self.reset_quarantine_folder)
        reset_folder_btn.setStyleSheet("padding: 8px 16px;")
        quarantine_btn_layout.addWidget(reset_folder_btn)
        quarantine_btn_layout.addStretch()
        quarantine_layout.addLayout(quarantine_btn_layout)

        # 정보 레이블
        info_label = QLabel("💡 격리 폴더를 변경하면 기존 격리 파일은 이동되지 않습니다.")
        info_label.setStyleSheet("color: #7f8c8d; font-size: 11px; padding: 5px;")
        info_label.setWordWrap(True)
        quarantine_layout.addWidget(info_label)

        quarantine_group.setLayout(quarantine_layout)
        layout.addWidget(quarantine_group)

        # 시그니처 추가
        sig_group = QGroupBox("🔐 시그니처 관리")
        sig_layout = QVBoxLayout()

        sig_form = QHBoxLayout()
        sig_form.addWidget(QLabel("이름:"))
        self.sig_name_input = QLineEdit()
        self.sig_name_input.setPlaceholderText("예: MyMalware.Generic")
        sig_form.addWidget(self.sig_name_input)

        sig_form.addWidget(QLabel("패턴:"))
        self.sig_pattern_input = QLineEdit()
        self.sig_pattern_input.setPlaceholderText("예: malicious_string")
        sig_form.addWidget(self.sig_pattern_input)

        sig_form.addWidget(QLabel("위험도:"))
        self.sig_severity_input = QSpinBox()
        self.sig_severity_input.setRange(1, 4)
        self.sig_severity_input.setValue(3)
        sig_form.addWidget(self.sig_severity_input)

        add_sig_btn = QPushButton('➕ 추가')
        add_sig_btn.clicked.connect(self.add_signature)
        sig_form.addWidget(add_sig_btn)

        sig_layout.addLayout(sig_form)
        sig_group.setLayout(sig_layout)
        layout.addWidget(sig_group)

        # 해시 추가
        hash_group = QGroupBox("🔑 악성 해시 관리")
        hash_layout = QVBoxLayout()

        hash_form = QHBoxLayout()
        hash_form.addWidget(QLabel("해시:"))
        self.hash_value_input = QLineEdit()
        self.hash_value_input.setPlaceholderText("MD5 또는 SHA256")
        hash_form.addWidget(self.hash_value_input)

        hash_form.addWidget(QLabel("위협:"))
        self.hash_name_input = QLineEdit()
        self.hash_name_input.setPlaceholderText("예: Trojan.Generic")
        hash_form.addWidget(self.hash_name_input)

        hash_form.addWidget(QLabel("유형:"))
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["MD5", "SHA256"])
        hash_form.addWidget(self.hash_type_combo)

        hash_form.addWidget(QLabel("위험도:"))
        self.hash_severity_input = QSpinBox()
        self.hash_severity_input.setRange(1, 4)
        self.hash_severity_input.setValue(4)
        hash_form.addWidget(self.hash_severity_input)

        add_hash_btn = QPushButton('➕ 추가')
        add_hash_btn.clicked.connect(self.add_hash)
        hash_form.addWidget(add_hash_btn)

        hash_layout.addLayout(hash_form)
        hash_group.setLayout(hash_layout)
        layout.addWidget(hash_group)

        layout.addStretch()
        tab.setLayout(layout)
        return tab

    def create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 히스토리 테이블
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(["시간", "스캔 유형", "총 파일", "위협 발견", "상태"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.history_table)

        # 버튼
        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton('🔄 새로고침')
        refresh_btn.clicked.connect(self.refresh_history)
        btn_layout.addWidget(refresh_btn)

        clear_btn = QPushButton('🗑️ 히스토리 지우기')
        clear_btn.clicked.connect(self.clear_history)
        btn_layout.addWidget(clear_btn)

        layout.addLayout(btn_layout)
        tab.setLayout(layout)
        self.refresh_history()
        return tab

    def create_help_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # 도움말 텍스트
        self.help_text = QTextEdit()
        self.help_text.setReadOnly(True)
        self.update_help_text_style()
        layout.addWidget(self.help_text)

        # 하단 버튼
        btn_layout = QHBoxLayout()
        docs_btn = QPushButton('📚 문서 폴더 열기')
        docs_btn.clicked.connect(self.open_docs_folder)
        docs_btn.setStyleSheet("padding: 8px 16px;")
        btn_layout.addWidget(docs_btn)

        btn_layout.addStretch()

        about_btn = QPushButton('ℹ️ 정보')
        about_btn.clicked.connect(self.show_about)
        about_btn.setStyleSheet("padding: 8px 16px;")
        btn_layout.addWidget(about_btn)

        layout.addLayout(btn_layout)
        tab.setLayout(layout)
        return tab

    def update_help_text_style(self):
        """도움말 텍스트 스타일 업데이트 (다크모드 대응)"""
        if self.dark_mode:
            # 다크모드용 스타일
            bg_color = "#2b2b2b"
            text_color = "#e0e0e0"
            border_color = "#555555"
            h1_color = "#5dade2"
            h2_color = "#85c1e9"
            feature_bg = "#3a3a3a"
            warning_bg = "#4a4a2a"
            warning_border = "#ffc107"
            tip_bg = "#2a3a4a"
            tip_border = "#17a2b8"
            code_bg = "#1e1e1e"
        else:
            # 라이트모드용 스타일
            bg_color = "#ffffff"
            text_color = "#333333"
            border_color = "#cccccc"
            h1_color = "#2c3e50"
            h2_color = "#34495e"
            feature_bg = "#ecf0f1"
            warning_bg = "#fff3cd"
            warning_border = "#ffc107"
            tip_bg = "#d1ecf1"
            tip_border = "#17a2b8"
            code_bg = "#f8f9fa"

        self.help_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 3px;
                padding: 8px;
            }}
        """)

        help_html = f"""
<html>
<head>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: {text_color}; background-color: {bg_color}; }}
h1 {{ color: {h1_color}; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
h2 {{ color: {h2_color}; margin-top: 20px; border-left: 4px solid #3498db; padding-left: 10px; }}
h3 {{ color: #7f8c8d; margin-top: 15px; }}
.feature {{ background-color: {feature_bg}; padding: 10px; margin: 10px 0; border-radius: 5px; }}
.warning {{ background-color: {warning_bg}; padding: 10px; margin: 10px 0; border-left: 4px solid {warning_border}; }}
.tip {{ background-color: {tip_bg}; padding: 10px; margin: 10px 0; border-left: 4px solid {tip_border}; }}
code {{ background-color: {code_bg}; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; }}
ul {{ margin-left: 20px; }}
li {{ margin: 5px 0; }}
</style>
</head>
<body>
<h1>🛡️ InfraRed V2.0 - 사용 가이드</h1>

<h2>📊 대시보드</h2>
<div class="feature">
<p><strong>실시간 통계 확인</strong></p>
<ul>
<li><strong>통계 카드:</strong> 총 스캔, 정상, 악성, 의심 파일 개수 표시</li>
<li><strong>파이 차트:</strong> 스캔 결과 분포를 시각적으로 표시 (스캔 완료 시 업데이트)</li>
<li><strong>최근 위협:</strong> 발견된 위협 목록 실시간 표시</li>
<li><strong>시스템 정보:</strong> 엔진 버전, 격리 파일 개수 등</li>
</ul>
</div>

<h2>🔍 파일 검사</h2>
<div class="feature">
<p><strong>다양한 스캔 옵션</strong></p>
<ul>
<li><strong>📄 파일 선택:</strong> 개별 파일 선택하여 검사</li>
<li><strong>📁 폴더 검사:</strong> 특정 폴더 전체 검사</li>
<li><strong>💻 전체 시스템 검사:</strong> C:\\ 드라이브 전체 검사 (최대 10,000개 파일)</li>
<li><strong>💿 드라이브 선택 검사:</strong> 특정 드라이브 선택하여 검사</li>
<li><strong>🖥️ 모든 드라이브 검사:</strong> 모든 드라이브 한 번에 검사</li>
<li><strong>🔌 USB 검사:</strong> USB 드라이브만 자동 탐지하여 검사</li>
</ul>
<p><strong>검사 옵션</strong></p>
<ul>
<li><strong>상세 스캔:</strong> MD5, SHA256, 엔트로피 등 상세 정보 표시</li>
<li><strong>자동 격리:</strong> 악성 파일 발견 시 자동으로 격리</li>
<li><strong>하위 폴더 포함:</strong> 폴더 검사 시 하위 폴더까지 검사</li>
</ul>
</div>

<div class="tip">
<strong>💡 팁:</strong> 스캔 중 <strong>⏹️ 검사 중지</strong> 버튼으로 언제든지 중지할 수 있습니다.
</div>

<h2>🗂️ 격리 구역</h2>
<div class="feature">
<p><strong>악성 파일 안전 관리</strong></p>
<ul>
<li><strong>격리:</strong> 악성 파일을 안전한 격리 폴더로 이동</li>
<li><strong>복원:</strong> 격리된 파일을 원래 위치로 복원</li>
<li><strong>영구 삭제:</strong> 격리된 파일 완전 삭제</li>
<li><strong>전체 비우기:</strong> 모든 격리 파일 한 번에 삭제</li>
</ul>
<p><strong>파일 핸들 강제 종료 (NEW!)</strong></p>
<ul>
<li>파일 사용 중인 프로세스 자동 탐지 및 종료</li>
<li>최대 5번 재시도로 안정적인 격리</li>
<li>시스템 프로세스는 자동 제외</li>
</ul>
</div>

<div class="warning">
<strong>⚠️ 주의:</strong> 격리 시 파일을 사용 중인 프로그램이 강제 종료될 수 있습니다. 저장하지 않은 데이터가 손실될 수 있으니 주의하세요.
</div>

<h2>👁️ 실시간 감시</h2>
<div class="feature">
<p><strong>폴더 실시간 모니터링</strong></p>
<ul>
<li>선택한 폴더에 새 파일 생성 시 자동 검사</li>
<li>실시간 로그 표시</li>
<li>언제든지 시작/중지 가능</li>
</ul>
</div>

<h2>⚙️ 설정</h2>
<div class="feature">
<p><strong>격리 폴더 설정 (NEW!)</strong></p>
<ul>
<li><strong>📂 폴더 변경:</strong> 원하는 위치로 격리 폴더 변경</li>
<li><strong>🔍 폴더 열기:</strong> 현재 격리 폴더를 탐색기에서 열기</li>
<li><strong>🔄 기본값으로:</strong> 기본 폴더로 재설정</li>
</ul>
<p><strong>시그니처 관리</strong></p>
<ul>
<li>사용자 정의 악성 패턴 추가</li>
<li>위험도 설정 (1~4)</li>
</ul>
<p><strong>해시 관리</strong></p>
<ul>
<li>MD5 또는 SHA256 해시 추가</li>
<li>알려진 악성 파일 데이터베이스 구축</li>
</ul>
</div>

<h2>📜 히스토리</h2>
<div class="feature">
<p><strong>스캔 기록 관리</strong></p>
<ul>
<li>모든 스캔 기록 자동 저장</li>
<li>시간, 스캔 유형, 결과 확인</li>
<li>최근 50개 기록 표시</li>
</ul>
</div>

<h2>🎨 기타 기능</h2>
<div class="feature">
<ul>
<li><strong>⚡ 빠른 스캔:</strong> 다운로드, 문서, 바탕화면 폴더 빠른 검사</li>
<li><strong>🌙 다크모드:</strong> 눈의 피로를 줄이는 다크 테마</li>
<li><strong>💾 결과 내보내기:</strong> 스캔 결과를 CSV 또는 JSON으로 저장</li>
</ul>
</div>

<h2>🔧 문제 해결</h2>
<div class="feature">
<h3>격리 실패 시</h3>
<ul>
<li><code>pip install psutil</code> 명령으로 psutil 설치</li>
<li>파일을 사용 중인 프로그램 수동으로 종료</li>
<li>관리자 권한으로 프로그램 실행</li>
</ul>
</div>

<h2>ℹ️ 버전 정보</h2>
<div class="feature">
<p><strong>버전:</strong> V2.0</p>
<p><strong>최종 업데이트:</strong> 2026-01-08</p>
</div>

</body>
</html>
"""
        self.help_text.setHtml(help_html)

    # ========================================================================
    # 기능 구현
    # ========================================================================

    def update_dashboard(self):
        # 통계 카드만 업데이트 (차트는 스캔 완료 시에만 업데이트)
        self.total_card.findChild(QLabel, "총 스캔_value").setText(str(self.stats.total_scanned))
        self.clean_card.findChild(QLabel, "정상_value").setText(str(self.stats.clean_files))
        self.malicious_card.findChild(QLabel, "악성_value").setText(str(self.stats.malicious_files))
        self.suspicious_card.findChild(QLabel, "의심_value").setText(str(self.stats.suspicious_files))

    def update_system_info(self):
        info = f"""
        <b>엔진 버전:</b> V2.0<br>
        <b>시그니처 DB:</b> 최신<br>
        <b>마지막 업데이트:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <b>격리된 파일:</b> {len(os.listdir(QUARANTINE_DIR)) if os.path.exists(QUARANTINE_DIR) else 0}개<br>
        <b>상세 스캔:</b> {'활성화' if has_detailed_scan else '비활성화'}<br>
        """
        self.system_info_label.setText(info)

    def quick_scan(self):
        # 빠른 스캔 (다운로드, 문서, 바탕화면)
        quick_paths = [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop")
        ]
        file_list = []
        for path in quick_paths:
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for name in files:
                        file_list.append(os.path.join(root, name))

        if file_list:
            self._start_batch_scan(file_list, "빠른 스캔")
        else:
            QMessageBox.information(self, "알림", "스캔할 파일이 없습니다.")

    def choose_and_scan(self):
        files, _ = QFileDialog.getOpenFileNames(self, "파일 선택")
        if files:
            self._start_batch_scan(files, "파일 스캔")

    def scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "폴더 선택")
        if folder:
            file_list = []
            if self.recursive_check.isChecked():
                for root, _, files in os.walk(folder):
                    for name in files:
                        file_list.append(os.path.join(root, name))
            else:
                file_list = [os.path.join(folder, f) for f in os.listdir(folder)
                             if os.path.isfile(os.path.join(folder, f))]

            if file_list:
                self._start_batch_scan(file_list, "폴더 스캔")
            else:
                QMessageBox.information(self, "알림", "스캔할 파일이 없습니다.")

    def full_system_scan(self):
        reply = QMessageBox.question(self, '전체 시스템 검사',
                                     '전체 시스템 검사는 시간이 오래 걸릴 수 있습니다.\n계속하시겠습니까?',
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            # C:\ 드라이브 전체 스캔 (Windows)
            if sys.platform.startswith("win"):
                root_path = "C:\\"
            else:
                root_path = "/"

            file_list = []
            for root, _, files in os.walk(root_path):
                for name in files:
                    file_list.append(os.path.join(root, name))
                    if len(file_list) > 10000:  # 최대 10000개 파일로 제한
                        break

            if file_list:
                self._start_batch_scan(file_list, "전체 시스템 스캔")

    def scan_drive(self):
        """특정 드라이브 선택 검사"""
        if sys.platform.startswith("win"):
            # Windows: 사용 가능한 드라이브 목록 가져오기
            import string
            available_drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    available_drives.append(drive)

            if not available_drives:
                QMessageBox.warning(self, "오류", "사용 가능한 드라이브가 없습니다.")
                return

            # 드라이브 선택 다이얼로그
            from PyQt5.QtWidgets import QInputDialog
            drive, ok = QInputDialog.getItem(self, "드라이브 선택",
                                             "검사할 드라이브를 선택하세요:",
                                             available_drives, 0, False)
            if ok and drive:
                reply = QMessageBox.question(self, '드라이브 검사',
                                             f'{drive} 드라이브 전체를 검사하시겠습니까?\n시간이 오래 걸릴 수 있습니다.',
                                             QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    file_list = []
                    try:
                        for root, _, files in os.walk(drive):
                            for name in files:
                                file_list.append(os.path.join(root, name))
                                if len(file_list) > 50000:  # 최대 50000개 파일로 제한
                                    break
                    except Exception as e:
                        QMessageBox.warning(self, "오류", f"드라이브 접근 오류:\n{e}")
                        return

                    if file_list:
                        self._start_batch_scan(file_list, f"{drive} 드라이브 스캔")
                    else:
                        QMessageBox.information(self, "알림", "스캔할 파일이 없습니다.")
        else:
            # Linux/Mac: 폴더 선택
            folder = QFileDialog.getExistingDirectory(self, "검사할 폴더 선택")
            if folder:
                self.scan_folder()

    def scan_all_drives(self):
        """모든 드라이브 검사"""
        if sys.platform.startswith("win"):
            import string
            available_drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    available_drives.append(drive)

            if not available_drives:
                QMessageBox.warning(self, "오류", "사용 가능한 드라이브가 없습니다.")
                return

            reply = QMessageBox.question(self, '모든 드라이브 검사',
                                         f'모든 드라이브를 검사하시겠습니까?\n'
                                         f'발견된 드라이브: {", ".join(available_drives)}\n\n'
                                         f'⚠️ 시간이 매우 오래 걸릴 수 있습니다!',
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                file_list = []
                scanned_drives = []
                for drive in available_drives:
                    try:
                        drive_files = 0
                        for root, _, files in os.walk(drive):
                            for name in files:
                                file_list.append(os.path.join(root, name))
                                drive_files += 1
                                if len(file_list) > 100000:  # 최대 100000개 파일로 제한
                                    break
                        scanned_drives.append(f"{drive} ({drive_files}개)")
                    except Exception as e:
                        print(f"드라이브 {drive} 스캔 오류: {e}")
                        continue

                if file_list:
                    self._start_batch_scan(file_list, f"모든 드라이브 스캔 ({', '.join(scanned_drives)})")
                else:
                    QMessageBox.information(self, "알림", "스캔할 파일이 없습니다.")
        else:
            QMessageBox.information(self, "알림", "이 기능은 Windows에서만 사용 가능합니다.")

    def scan_usb(self):
        """USB 드라이브 검사"""
        if sys.platform.startswith("win"):
            import string
            # 이동식 드라이브 찾기
            usb_drives = []
            try:
                import ctypes
                for letter in string.ascii_uppercase:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        # GetDriveType으로 이동식 드라이브 확인
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                        # DRIVE_REMOVABLE = 2
                        if drive_type == 2:
                            usb_drives.append(drive)
            except Exception as e:
                print(f"USB 드라이브 탐지 오류: {e}")
                # 대체 방법: 모든 드라이브 표시
                for letter in string.ascii_uppercase:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive) and letter not in ['C', 'D']:  # C, D 제외
                        usb_drives.append(drive)

            if not usb_drives:
                QMessageBox.information(self, "알림", "USB 드라이브를 찾을 수 없습니다.\n\n"
                                                     "USB 장치가 연결되어 있는지 확인하세요.")
                return

            # USB 드라이브 선택
            from PyQt5.QtWidgets import QInputDialog
            if len(usb_drives) == 1:
                selected_drive = usb_drives[0]
            else:
                selected_drive, ok = QInputDialog.getItem(self, "USB 선택",
                                                          "검사할 USB 드라이브를 선택하세요:",
                                                          usb_drives, 0, False)
                if not ok:
                    return

            reply = QMessageBox.question(self, 'USB 검사',
                                         f'{selected_drive} USB를 검사하시겠습니까?',
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                file_list = []
                try:
                    for root, _, files in os.walk(selected_drive):
                        for name in files:
                            file_list.append(os.path.join(root, name))
                            if len(file_list) > 50000:  # 최대 50000개 파일로 제한
                                break
                except Exception as e:
                    QMessageBox.warning(self, "오류", f"USB 접근 오류:\n{e}")
                    return

                if file_list:
                    self._start_batch_scan(file_list, f"USB 스캔 ({selected_drive})")
                else:
                    QMessageBox.information(self, "알림", "스캔할 파일이 없습니다.")
        else:
            QMessageBox.information(self, "알림", "이 기능은 Windows에서만 사용 가능합니다.")

    def _start_batch_scan(self, files, scan_type="스캔"):
        if not files:
            return

        self.result_table.setRowCount(0)
        self.progress.setMaximum(len(files))
        self.progress.setValue(0)
        self.progress_label.setText(f"{scan_type} 시작... (총 {len(files)}개 파일)")

        # 버튼 상태 변경
        self.select_btn.setEnabled(False)
        self.folder_btn.setEnabled(False)
        self.full_scan_btn.setEnabled(False)
        self.drive_scan_btn.setEnabled(False)
        self.all_drives_btn.setEnabled(False)
        self.usb_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)

        self.scan_thread = BatchScanThread(files, self.detailed_check.isChecked())
        self.scan_thread.progress.connect(self.progress.setValue)
        self.scan_thread.result_detailed.connect(self.add_result_to_table)
        self.scan_thread.stats_update.connect(self.update_stats)
        self.scan_thread.finished.connect(lambda: self.scan_finished(scan_type, len(files)))
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            reply = QMessageBox.question(self, '스캔 중지', '정말로 스캔을 중지하시겠습니까?',
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.scan_thread.stop()
                self.progress_label.setText("스캔 중지 중...")
                self.stop_scan_btn.setEnabled(False)

    def add_result_to_table(self, result):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        filepath = result.get('filepath', '')
        filename = os.path.basename(filepath)
        status = result.get('status', -1)
        threat = result.get('threat_name', 'Unknown')
        md5 = result.get('md5', '')[:16] + "..." if result.get('md5') else ""
        size = result.get('file_size', 0)

        status_map = {0: "✅ 정상", 1: "🔴 악성", 2: "🔴 악성", 3: "⚠️ 의심", -1: "❌ 오류"}
        status_text = status_map.get(status, "❓ 알수없음")

        self.result_table.setItem(row, 0, QTableWidgetItem(filename))
        self.result_table.setItem(row, 1, QTableWidgetItem(status_text))
        self.result_table.setItem(row, 2, QTableWidgetItem(threat))
        self.result_table.setItem(row, 3, QTableWidgetItem(md5))
        self.result_table.setItem(row, 4, QTableWidgetItem(f"{size} bytes"))

        # 작업 버튼
        if status in [1, 2, 3]:  # 악성 또는 의심
            quarantine_btn = QPushButton('🗂️ 격리')
            quarantine_btn.clicked.connect(lambda: self.quarantine_file(filepath, threat))
            self.result_table.setCellWidget(row, 5, quarantine_btn)

            # 최근 위협 목록에 추가
            self.recent_threats_list.addItem(f"[{datetime.now().strftime('%H:%M:%S')}] {threat} - {filename}")

            # 자동 격리
            if self.auto_quarantine_check.isChecked():
                self.quarantine_file(filepath, threat)

    def update_stats(self, stats):
        self.stats.total_scanned = stats['total']
        self.stats.clean_files = stats['clean']
        self.stats.malicious_files = stats['malicious']
        self.stats.suspicious_files = stats['suspicious']
        self.stats.errors = stats['errors']
        self.progress_label.setText(f"진행 중... 정상: {stats['clean']}, 악성: {stats['malicious']}, 의심: {stats['suspicious']}")

    def scan_finished(self, scan_type, total_files):
        # 진행바 100%로 설정
        self.progress.setValue(self.progress.maximum())
        self.progress_label.setText(f"✅ 검사 완료! (정상: {self.stats.clean_files}, 악성: {self.stats.malicious_files}, 의심: {self.stats.suspicious_files})")

        # 버튼 상태 복원
        self.select_btn.setEnabled(True)
        self.folder_btn.setEnabled(True)
        self.full_scan_btn.setEnabled(True)
        self.drive_scan_btn.setEnabled(True)
        self.all_drives_btn.setEnabled(True)
        self.usb_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)

        # 차트 업데이트 (스캔 완료 시에만)
        self.update_pie_chart()

        # 히스토리에 추가
        history_entry = {
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': scan_type,
            'total': total_files,
            'threats': self.stats.malicious_files + self.stats.suspicious_files,
            'status': '완료'
        }
        self.scan_history.append(history_entry)
        self.save_history()
        self.refresh_history()

        QMessageBox.information(self, "스캔 완료",
                                f"{scan_type} 완료!\n\n"
                                f"총 파일: {total_files}\n"
                                f"정상: {self.stats.clean_files}\n"
                                f"악성: {self.stats.malicious_files}\n"
                                f"의심: {self.stats.suspicious_files}")

    def quarantine_file(self, filepath, threat_name):
        import time
        import gc
        import subprocess

        try:
            if not os.path.exists(filepath):
                QMessageBox.warning(self, "오류", "파일을 찾을 수 없습니다.")
                return

            # 한글 파일명을 안전한 형식으로 변환
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # 파일 확장자 분리
            name_part, ext_part = os.path.splitext(filename)

            # 안전한 파일명 생성 (영문+숫자만 사용)
            import hashlib
            safe_name = hashlib.md5(name_part.encode('utf-8')).hexdigest()[:8]
            quarantine_filename = f"{timestamp}_{safe_name}{ext_part}"
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

            # 가비지 컬렉션 강제 실행 (파일 핸들 해제)
            gc.collect()

            # 파일을 사용 중인 프로세스 강제 종료 함수
            def force_close_file_handles(file_path):
                """psutil을 사용하여 파일을 사용 중인 프로세스 찾기 및 종료"""
                try:
                    import psutil
                    # 절대 경로로 변환
                    abs_path = os.path.abspath(file_path).lower()
                    closed_count = 0

                    # 모든 프로세스 검사
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            # 프로세스가 열고 있는 파일 목록 확인
                            for item in proc.open_files():
                                if item.path.lower() == abs_path:
                                    print(f"[격리] 파일 사용 중인 프로세스 발견: {proc.info['name']} (PID: {proc.info['pid']})")

                                    # 중요 시스템 프로세스는 건너뛰기
                                    if proc.info['name'].lower() in ['system', 'csrss.exe', 'smss.exe', 'wininit.exe']:
                                        continue

                                    # 프로세스 강제 종료
                                    proc.kill()
                                    closed_count += 1
                                    print(f"[격리] 프로세스 종료됨: {proc.info['name']}")
                                    time.sleep(0.3)
                                    break
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue

                    return closed_count > 0
                except ImportError:
                    print("[경고] psutil이 설치되지 않았습니다. 파일 핸들 강제 종료를 건너뜁니다.")
                    print("       설치: pip install psutil")
                    return False
                except Exception as e:
                    print(f"[오류] 파일 핸들 종료 실패: {e}")
                    return False

            # 파일 복사 재시도 로직
            max_retries = 5
            success = False
            last_error = None

            for attempt in range(max_retries):
                try:
                    # 파일을 바이너리 모드로 읽어서 복사 (핸들 즉시 해제)
                    with open(filepath, 'rb') as src:
                        file_data = src.read()

                    with open(quarantine_path, 'wb') as dst:
                        dst.write(file_data)

                    # 원본 파일 삭제 시도
                    time.sleep(0.2)

                    # Windows에서 파일 속성 변경 (읽기 전용 해제)
                    if sys.platform.startswith("win"):
                        try:
                            subprocess.run(['attrib', '-R', filepath], capture_output=True, timeout=2)
                        except:
                            pass

                    os.remove(filepath)
                    success = True
                    break

                except PermissionError as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        print(f"[격리] 시도 {attempt + 1}/{max_retries} 실패: {e}")
                        # 재시도 전 대기 시간 증가
                        time.sleep(0.5 * (attempt + 1))
                        gc.collect()

                        # 3번째 시도부터 파일 핸들 강제 종료
                        if attempt >= 2:
                            print(f"[격리] 파일 핸들 강제 종료 시도...")
                            if force_close_file_handles(filepath):
                                time.sleep(1.0)  # 프로세스 종료 후 대기
                        continue
                    else:
                        # 마지막 시도 실패
                        success = False
                        break

                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(0.5)
                        continue
                    else:
                        raise e

            if not success:
                # 복사는 성공했지만 원본 삭제 실패
                error_msg = str(last_error) if last_error else "알 수 없는 오류"
                reply = QMessageBox.question(self, '파일 사용 중',
                                             f'파일이 다른 프로그램에서 사용 중입니다.\n\n'
                                             f'파일: {filename}\n'
                                             f'오류: {error_msg}\n\n'
                                             f'격리 폴더에 복사는 완료되었습니다.\n'
                                             f'원본 파일은 삭제되지 않았습니다.\n\n'
                                             f'파일을 사용 중인 프로그램을 모두 닫고\n'
                                             f'수동으로 삭제하시겠습니까?',
                                             QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    # 파일 탐색기에서 파일 위치 열기
                    try:
                        if sys.platform.startswith("win"):
                            subprocess.run(['explorer', '/select,', filepath])
                    except:
                        pass
                    QMessageBox.information(self, "수동 삭제 필요",
                                            f"다음 파일을 수동으로 삭제해주세요:\n\n{filepath}\n\n"
                                            f"파일 탐색기가 열렸습니다.\n"
                                            f"파일을 사용 중인 프로그램을 모두 닫은 후 삭제하세요.")

            # 메타데이터 저장 (UTF-8 인코딩 명시)
            meta_path = quarantine_path + ".meta"
            with open(meta_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'original_path': filepath,
                    'original_filename': filename,
                    'threat_name': threat_name,
                    'quarantine_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'original_deleted': success
                }, f, ensure_ascii=False, indent=2)

            self.stats.quarantined += 1
            self.refresh_quarantine()

            if success:
                QMessageBox.information(self, "성공", f"파일이 격리되었습니다:\n{filename}")
            else:
                QMessageBox.warning(self, "부분 성공",
                                    f"파일이 격리 폴더에 복사되었지만\n원본 파일은 삭제되지 않았습니다:\n{filename}\n\n"
                                    f"파일을 사용 중인 프로그램을 닫고 수동으로 삭제하세요.")

        except Exception as e:
            QMessageBox.critical(self, "오류", f"격리 실패:\n{e}")

    def refresh_quarantine(self):
        self.quarantine_table.setRowCount(0)
        if not os.path.exists(QUARANTINE_DIR):
            return

        for filename in os.listdir(QUARANTINE_DIR):
            if filename.endswith('.meta'):
                continue

            filepath = os.path.join(QUARANTINE_DIR, filename)
            meta_path = filepath + ".meta"

            threat_name = "Unknown"
            quarantine_time = "Unknown"
            original_filename = filename

            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)
                        threat_name = meta.get('threat_name', 'Unknown')
                        quarantine_time = meta.get('quarantine_time', 'Unknown')
                        original_filename = meta.get('original_filename', filename)
                except:
                    pass

            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            self.quarantine_table.setItem(row, 0, QTableWidgetItem(original_filename))
            self.quarantine_table.setItem(row, 1, QTableWidgetItem(quarantine_time))
            self.quarantine_table.setItem(row, 2, QTableWidgetItem(threat_name))

            # 작업 버튼
            btn_widget = QWidget()
            btn_layout = QHBoxLayout()
            btn_layout.setContentsMargins(0, 0, 0, 0)

            restore_btn = QPushButton('↩️')
            restore_btn.clicked.connect(lambda checked, f=filepath: self.restore_file(f))
            btn_layout.addWidget(restore_btn)

            delete_btn = QPushButton('🗑️')
            delete_btn.clicked.connect(lambda checked, f=filepath: self.delete_file(f))
            btn_layout.addWidget(delete_btn)

            btn_widget.setLayout(btn_layout)
            self.quarantine_table.setCellWidget(row, 3, btn_widget)

    def restore_file(self, filepath):
        try:
            # 격리 파일이 존재하는지 확인
            if not os.path.exists(filepath):
                QMessageBox.warning(self, "오류", "격리된 파일을 찾을 수 없습니다.")
                return

            meta_path = filepath + ".meta"

            # 메타 파일이 없으면 경고만 하고 복원은 진행
            if not os.path.exists(meta_path):
                reply = QMessageBox.question(self, '메타데이터 없음',
                                             '메타데이터 파일이 없습니다.\n격리 파일만 삭제하시겠습니까?',
                                             QMessageBox.Yes | QMessageBox.No)
                if reply == QMessageBox.Yes:
                    os.remove(filepath)
                    self.refresh_quarantine()
                    QMessageBox.information(self, "완료", "격리 파일이 삭제되었습니다.")
                return

            # 메타 파일 읽기
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)

            original_path = meta.get('original_path')
            if not original_path:
                QMessageBox.warning(self, "오류", "원본 경로 정보가 없습니다.")
                return

            # 원본 경로의 디렉토리가 존재하는지 확인
            original_dir = os.path.dirname(original_path)
            if not os.path.exists(original_dir):
                os.makedirs(original_dir)

            # 파일 복사 후 격리 파일 삭제
            shutil.copy2(filepath, original_path)
            os.remove(filepath)
            os.remove(meta_path)

            self.refresh_quarantine()
            QMessageBox.information(self, "성공", "파일이 복원되었습니다.")

        except Exception as e:
            QMessageBox.critical(self, "오류", f"복원 실패:\n{e}")

    def delete_file(self, filepath):
        reply = QMessageBox.question(self, '확인', '파일을 영구적으로 삭제하시겠습니까?',
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                os.remove(filepath)
                meta_path = filepath + ".meta"
                if os.path.exists(meta_path):
                    os.remove(meta_path)
                self.refresh_quarantine()
                QMessageBox.information(self, "성공", "파일이 삭제되었습니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"삭제 실패:\n{e}")

    def restore_from_quarantine(self):
        selected = self.quarantine_table.currentRow()
        if selected >= 0:
            filename = self.quarantine_table.item(selected, 0).text()
            filepath = os.path.join(QUARANTINE_DIR, filename)
            self.restore_file(filepath)
        else:
            QMessageBox.warning(self, "경고", "복원할 파일을 선택하세요.")

    def delete_from_quarantine(self):
        selected = self.quarantine_table.currentRow()
        if selected >= 0:
            filename = self.quarantine_table.item(selected, 0).text()
            filepath = os.path.join(QUARANTINE_DIR, filename)
            self.delete_file(filepath)
        else:
            QMessageBox.warning(self, "경고", "삭제할 파일을 선택하세요.")

    def clear_quarantine(self):
        reply = QMessageBox.question(self, '확인', '격리 구역의 모든 파일을 삭제하시겠습니까?',
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                for filename in os.listdir(QUARANTINE_DIR):
                    filepath = os.path.join(QUARANTINE_DIR, filename)
                    os.remove(filepath)
                self.refresh_quarantine()
                QMessageBox.information(self, "성공", "격리 구역이 비워졌습니다.")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"삭제 실패:\n{e}")

    def toggle_monitoring(self, checked):
        if checked:
            dir_ = QFileDialog.getExistingDirectory(self, "감시할 폴더 선택")
            if not dir_:
                self.monitor_btn.setChecked(False)
                return

            self.monitor_btn.setText("⏹️ 실시간 감시 중지")
            self.monitor_path_label.setText(f"감시 중: {dir_}")
            self.monitor_log.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] 실시간 감시 시작: {dir_}\n")

            self.observer = Observer()
            handler = FolderHandler(lambda msg: self.monitor_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"))
            self.observer.schedule(handler, dir_, recursive=False)
            self.observer.start()
        else:
            try:
                self.observer.stop()
                self.observer.join()
                self.monitor_log.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] 실시간 감시 중지\n")
                self.monitor_path_label.setText("감시 중인 폴더: 없음")
            except:
                pass
            self.monitor_btn.setText("▶️ 실시간 감시 시작")

    def add_signature(self):
        if not has_add_signature:
            QMessageBox.warning(self, "기능 없음", "현재 DLL은 시그니처 추가를 지원하지 않습니다.")
            return

        name = self.sig_name_input.text().strip()
        pattern = self.sig_pattern_input.text().strip()
        severity = self.sig_severity_input.value()

        if not name or not pattern:
            QMessageBox.warning(self, "경고", "이름과 패턴을 입력하세요!")
            return

        try:
            count = engine.add_signature(name.encode('utf-8'), pattern.encode('utf-8'), severity)
            QMessageBox.information(self, "성공",
                                    f"시그니처 추가 완료!\n\n"
                                    f"이름: {name}\n"
                                    f"패턴: {pattern}\n"
                                    f"위험도: {severity}\n"
                                    f"총 시그니처: {count}")
            self.sig_name_input.clear()
            self.sig_pattern_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "오류", f"시그니처 추가 실패:\n{e}")

    def add_hash(self):
        if not has_add_hash:
            QMessageBox.warning(self, "기능 없음", "현재 DLL은 해시 추가를 지원하지 않습니다.")
            return

        hash_value = self.hash_value_input.text().strip().lower()
        threat_name = self.hash_name_input.text().strip()
        severity = self.hash_severity_input.value()
        is_sha256 = (self.hash_type_combo.currentText() == "SHA256")

        if not hash_value or not threat_name:
            QMessageBox.warning(self, "경고", "해시와 위협 이름을 입력하세요!")
            return

        expected_len = 64 if is_sha256 else 32
        if len(hash_value) != expected_len:
            QMessageBox.warning(self, "경고", f"{'SHA256' if is_sha256 else 'MD5'} 해시는 {expected_len}자여야 합니다!")
            return

        try:
            count = engine.add_hash(hash_value.encode('utf-8'), threat_name.encode('utf-8'), severity, is_sha256)
            QMessageBox.information(self, "성공",
                                    f"해시 추가 완료!\n\n"
                                    f"해시: {hash_value}\n"
                                    f"위협: {threat_name}\n"
                                    f"유형: {'SHA256' if is_sha256 else 'MD5'}\n"
                                    f"총 해시: {count}")
            self.hash_value_input.clear()
            self.hash_name_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "오류", f"해시 추가 실패:\n{e}")

    def change_quarantine_folder(self):
        """격리 폴더 변경"""
        global QUARANTINE_DIR
        new_folder = QFileDialog.getExistingDirectory(self, "격리 폴더 선택", QUARANTINE_DIR)

        if new_folder:
            # 폴더가 존재하는지 확인
            if not os.path.exists(new_folder):
                try:
                    os.makedirs(new_folder)
                except Exception as e:
                    QMessageBox.critical(self, "오류", f"폴더 생성 실패:\n{e}")
                    return

            # 설정 저장
            SETTINGS['quarantine_dir'] = new_folder
            if save_settings(SETTINGS):
                QUARANTINE_DIR = new_folder
                self.quarantine_path_label.setText(QUARANTINE_DIR)
                QMessageBox.information(self, "성공",
                                        f"격리 폴더가 변경되었습니다:\n\n{QUARANTINE_DIR}\n\n"
                                        f"⚠️ 기존 격리 파일은 이전 폴더에 남아있습니다.")
                # 격리 구역 탭 새로고침
                self.refresh_quarantine()
            else:
                QMessageBox.critical(self, "오류", "설정 저장에 실패했습니다.")

    def open_quarantine_folder(self):
        """격리 폴더 열기"""
        if os.path.exists(QUARANTINE_DIR):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(QUARANTINE_DIR)
                elif sys.platform.startswith("darwin"):  # macOS
                    os.system(f'open "{QUARANTINE_DIR}"')
                else:  # Linux
                    os.system(f'xdg-open "{QUARANTINE_DIR}"')
            except Exception as e:
                QMessageBox.warning(self, "오류", f"폴더 열기 실패:\n{e}")
        else:
            QMessageBox.warning(self, "오류", "격리 폴더가 존재하지 않습니다.")

    def reset_quarantine_folder(self):
        """격리 폴더를 기본값으로 재설정"""
        global QUARANTINE_DIR
        reply = QMessageBox.question(self, '확인',
                                     '격리 폴더를 기본값으로 재설정하시겠습니까?\n\n'
                                     '기본 폴더: python_gui/quarantine',
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            default_folder = os.path.join(os.path.dirname(__file__), "quarantine")

            # 폴더가 존재하지 않으면 생성
            if not os.path.exists(default_folder):
                try:
                    os.makedirs(default_folder)
                except Exception as e:
                    QMessageBox.critical(self, "오류", f"폴더 생성 실패:\n{e}")
                    return

            # 설정 저장
            SETTINGS['quarantine_dir'] = default_folder
            if save_settings(SETTINGS):
                QUARANTINE_DIR = default_folder
                self.quarantine_path_label.setText(QUARANTINE_DIR)
                QMessageBox.information(self, "성공", "격리 폴더가 기본값으로 재설정되었습니다.")
                # 격리 구역 탭 새로고침
                self.refresh_quarantine()
            else:
                QMessageBox.critical(self, "오류", "설정 저장에 실패했습니다.")

    def export_results(self):
        filename, _ = QFileDialog.getSaveFileName(self, "결과 내보내기", "",
                                                  "CSV Files (*.csv);;JSON Files (*.json);;All Files (*)")
        if filename:
            try:
                if filename.endswith('.json'):
                    results = []
                    for row in range(self.result_table.rowCount()):
                        results.append({
                            'filename': self.result_table.item(row, 0).text(),
                            'status': self.result_table.item(row, 1).text(),
                            'threat': self.result_table.item(row, 2).text(),
                            'md5': self.result_table.item(row, 3).text(),
                            'size': self.result_table.item(row, 4).text()
                        })
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2, ensure_ascii=False)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("파일명,상태,위협,MD5,크기\n")
                        for row in range(self.result_table.rowCount()):
                            f.write(f"{self.result_table.item(row, 0).text()},"
                                    f"{self.result_table.item(row, 1).text()},"
                                    f"{self.result_table.item(row, 2).text()},"
                                    f"{self.result_table.item(row, 3).text()},"
                                    f"{self.result_table.item(row, 4).text()}\n")
                QMessageBox.information(self, "성공", "결과가 저장되었습니다!")
            except Exception as e:
                QMessageBox.critical(self, "오류", f"저장 실패:\n{e}")

    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.scan_history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"히스토리 저장 실패: {e}")

    def refresh_history(self):
        self.history_table.setRowCount(0)
        for entry in reversed(self.scan_history[-50:]):  # 최근 50개만 표시
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            self.history_table.setItem(row, 0, QTableWidgetItem(entry['time']))
            self.history_table.setItem(row, 1, QTableWidgetItem(entry['type']))
            self.history_table.setItem(row, 2, QTableWidgetItem(str(entry['total'])))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(entry['threats'])))
            self.history_table.setItem(row, 4, QTableWidgetItem(entry['status']))

    def clear_history(self):
        reply = QMessageBox.question(self, '확인', '히스토리를 모두 삭제하시겠습니까?',
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.scan_history = []
            self.save_history()
            self.refresh_history()
            QMessageBox.information(self, "성공", "히스토리가 삭제되었습니다.")

    def open_docs_folder(self):
        """문서 폴더 열기"""
        docs_folder = os.path.dirname(os.path.abspath(__file__))
        parent_folder = os.path.dirname(docs_folder)  # antivirus_project 폴더

        if os.path.exists(parent_folder):
            try:
                if sys.platform.startswith("win"):
                    os.startfile(parent_folder)
                elif sys.platform.startswith("darwin"):  # macOS
                    os.system(f'open "{parent_folder}"')
                else:  # Linux
                    os.system(f'xdg-open "{parent_folder}"')
            except Exception as e:
                QMessageBox.warning(self, "오류", f"폴더 열기 실패:\n{e}")
        else:
            QMessageBox.warning(self, "오류", "문서 폴더를 찾을 수 없습니다.")

    def show_about(self):
        """정보 다이얼로그 표시"""
        about_text = f"""
<h2>🛡️ InfraRed</h2>
<p><b>버전:</b> 2.0</p>
<p><b>최종 업데이트:</b> 2026-01-08</p>
<br>
<p><b>주요 기능:</b></p>
<ul>
<li> 시그니처 기반 탐지</li>
<li> 해시 기반 탐지 (MD5/SHA256)</li>
<li> 휴리스틱 분석</li>
<li> 엔트로피 계산</li>
<li> 파일 핸들 강제 종료</li>
<li> 드라이브/USB 스캔</li>
<li> 격리 폴더 지정</li>
<li> 실시간 감시</li>
</ul>
<br>
<p><b>기술 스택:</b></p>
<ul>
<li>C++ 엔진 (OpenSSL)</li>
<li>Python GUI (PyQt5)</li>
<li>psutil (프로세스 관리)</li>
<li>watchdog (실시간 감시)</li>
</ul>
<br>
<br>
<p><b>격리 폴더:</b> {QUARANTINE_DIR}</p>
<p><b>DLL 위치:</b> {os.path.dirname(os.path.abspath(__file__))}</p>
"""
        QMessageBox.about(self, "정보", about_text)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        # 도움말 텍스트 스타일도 업데이트
        self.update_help_text_style()
        # 테마 버튼 텍스트 변경
        if self.dark_mode:
            self.theme_btn.setText("☀️ 라이트모드")
        else:
            self.theme_btn.setText("🌙 다크모드")

    def apply_theme(self):
        if self.dark_mode:
            # 다크 모드
            self.setStyleSheet("""
                QWidget {
                    background-color: #2b2b2b;
                    color: #ffffff;
                }
                QGroupBox {
                    border: 2px solid #555555;
                    border-radius: 5px;
                    margin-top: 10px;
                    padding-top: 10px;
                    font-weight: bold;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
                QPushButton {
                    background-color: #3a3a3a;
                    border: 1px solid #555555;
                    border-radius: 4px;
                    padding: 6px 12px;
                    color: #ffffff;
                }
                QPushButton:hover {
                    background-color: #4a4a4a;
                }
                QPushButton:pressed {
                    background-color: #2a2a2a;
                }
                QLineEdit, QTextEdit, QSpinBox, QComboBox {
                    background-color: #3a3a3a;
                    border: 1px solid #555555;
                    border-radius: 3px;
                    padding: 4px;
                    color: #ffffff;
                }
                QTableWidget {
                    background-color: #3a3a3a;
                    alternate-background-color: #2f2f2f;
                    gridline-color: #555555;
                }
                QHeaderView::section {
                    background-color: #4a4a4a;
                    padding: 4px;
                    border: 1px solid #555555;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #555555;
                    border-radius: 3px;
                    text-align: center;
                    background-color: #3a3a3a;
                }
                QProgressBar::chunk {
                    background-color: #3498db;
                }
                QListWidget {
                    background-color: #3a3a3a;
                    border: 1px solid #555555;
                    color: #ffffff;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                }
                QTabBar::tab {
                    background-color: #3a3a3a;
                    border: 1px solid #555555;
                    padding: 8px 16px;
                    color: #ffffff;
                }
                QTabBar::tab:selected {
                    background-color: #4a4a4a;
                }
                QLabel#quarantine_path_label {
                    color: #5dade2;
                    font-weight: bold;
                }
            """)
        else:
            # 라이트 모드
            self.setStyleSheet("""
                QWidget {
                    background-color: #f5f5f5;
                    color: #333333;
                }
                QGroupBox {
                    border: 2px solid #cccccc;
                    border-radius: 5px;
                    margin-top: 10px;
                    padding-top: 10px;
                    font-weight: bold;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 10px;
                    padding: 0 5px;
                }
                QPushButton {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    border-radius: 4px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #e8e8e8;
                }
                QPushButton:pressed {
                    background-color: #d0d0d0;
                }
                QLineEdit, QTextEdit, QSpinBox, QComboBox {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    padding: 4px;
                }
                QTableWidget {
                    background-color: #ffffff;
                    alternate-background-color: #f9f9f9;
                    gridline-color: #e0e0e0;
                }
                QHeaderView::section {
                    background-color: #e8e8e8;
                    padding: 4px;
                    border: 1px solid #cccccc;
                    font-weight: bold;
                }
                QProgressBar {
                    border: 1px solid #cccccc;
                    border-radius: 3px;
                    text-align: center;
                    background-color: #ffffff;
                }
                QProgressBar::chunk {
                    background-color: #3498db;
                }
                QListWidget {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                }
                QTabWidget::pane {
                    border: 1px solid #cccccc;
                }
                QTabBar::tab {
                    background-color: #ffffff;
                    border: 1px solid #cccccc;
                    padding: 8px 16px;
                }
                QTabBar::tab:selected {
                    background-color: #e8e8e8;
                }
                QLabel#quarantine_path_label {
                    color: #2c3e50;
                    font-weight: bold;
                }
            """)


if __name__ == "__main__":
    from PyQt5.QtGui import QPainter
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    win = AntivirusGUI()
    win.show()
    sys.exit(app.exec_())