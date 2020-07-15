from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize, QTimer
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QStyle, QSplitter, QLabel

import re
import threading

import binaryninjaui
from binaryninja import BinaryView, PythonScriptingInstance, InstructionTextToken, InstructionTextTokenType, DisassemblyTextLine, LinearDisassemblyLine, LinearDisassemblyLineType, HighlightStandardColor, core_version, interaction, BinaryViewType, AnalysisState
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import View, ViewType, UIAction, UIActionHandler, LinearView, DisassemblyContainer, ViewFrame, DockHandler, TokenizedTextView, HistoryEntry

from . import widget, ControlsWidget
from .. import binjaplug

(major, minor, buildid) = re.match(r'^(\d+)\.(\d+)\.?(\d+)?', core_version()).groups()
major = int(major)
minor = int(minor)
buildid = int(buildid) if buildid is not None else 0xffffffff

class DiffView(QWidget, View):
	def __init__(self, parent, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.src_bv = data

		fname = interaction.get_open_filename_input('File to Diff:').decode('utf-8')
		print('opening {}...'.format(fname))

		# open secondary file and begin non-blocking analysis
		self.dst_bv = BinaryViewType.get_view_of_file(fname, update_analysis=False)
		self.dst_bv.update_analysis()


		QWidget.__init__(self, parent)
		self.controls = ControlsWidget.DebugControlsWidget(self, "Controls", data)
		View.__init__(self)

		self.setupView(self)

		self.current_offset = 0

		self.splitter = QSplitter(Qt.Orientation.Horizontal, self)

		frame = ViewFrame.viewFrameForWidget(self)
		self.dst_editor = LinearView(self.dst_bv, frame)
		self.dst_editor.setAccessibleName('Destination Editor')
		self.src_editor = LinearView(self.src_bv, frame)
		self.src_editor.setAccessibleName('Source Editor')

		# sync location between src and dst panes
		self.sync = True

		self.binary_text = TokenizedTextView(self, self.src_bv)
		self.is_raw_disassembly = False
		self.raw_address = 0

		self.is_navigating_history = False
		self.memory_history_addr = 0

		# TODO: Handle these and change views accordingly
		# Currently they are just disabled as the DisassemblyContainer gets confused
		# about where to go and just shows a bad view
		self.src_editor.actionHandler().bindAction("View in Hex Editor", UIAction())
		self.src_editor.actionHandler().bindAction("View in Linear Disassembly", UIAction())
		self.src_editor.actionHandler().bindAction("View in Types View", UIAction())

		self.dst_editor.actionHandler().bindAction("View in Hex Editor", UIAction())
		self.dst_editor.actionHandler().bindAction("View in Disassembly Graph", UIAction())
		self.dst_editor.actionHandler().bindAction("View in Types View", UIAction())

		small_font = QApplication.font()
		small_font.setPointSize(11)

		bv_layout = QVBoxLayout()
		bv_layout.setSpacing(0)
		bv_layout.setContentsMargins(0, 0, 0, 0)

		bv_label = QLabel("Loaded File")
		bv_label.setFont(small_font)
		bv_layout.addWidget(bv_label)
		bv_layout.addWidget(self.src_editor)

		self.bv_widget = QWidget()
		self.bv_widget.setLayout(bv_layout)

		disasm_layout = QVBoxLayout()
		disasm_layout.setSpacing(0)
		disasm_layout.setContentsMargins(0, 0, 0, 0)

		disasm_label = QLabel("Raw Disassembly at PC")
		disasm_label.setFont(small_font)
		disasm_layout.addWidget(disasm_label)
		disasm_layout.addWidget(self.binary_text)

		self.disasm_widget = QWidget()
		self.disasm_widget.setLayout(disasm_layout)

		memory_layout = QVBoxLayout()
		memory_layout.setSpacing(0)
		memory_layout.setContentsMargins(0, 0, 0, 0)

		memory_label = QLabel("")
		memory_label.setFont(small_font)
		memory_layout.addWidget(memory_label)
		memory_layout.addWidget(self.dst_editor)

		self.memory_widget = QWidget()
		self.memory_widget.setLayout(memory_layout)

		self.splitter.addWidget(self.bv_widget)
		self.splitter.addWidget(self.memory_widget)

		# Equally sized
		self.splitter.setSizes([0x7fffffff, 0x7fffffff])

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.controls)
		layout.addWidget(self.splitter, 100)
		self.setLayout(layout)

		self.needs_update = True
		self.update_timer = QTimer(self)
		self.update_timer.setInterval(200)
		self.update_timer.setSingleShot(False)
		self.update_timer.timeout.connect(lambda: self.updateTimerEvent())

	def getData(self):
		return self.src_bv

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def getCurrentOffset(self):
		offset = self.src_editor.getCurrentOffset()
		return offset

	def getSelectionOffsets(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getSelectionOffsets()
		return (self.raw_address, self.raw_address)

	def getCurrentArchitecture(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentArchitecture()
		return None

	def getCurrentLowLevelILFunction(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentLowLevelILFunction()
		return None

	def getCurrentMediumLevelILFunction(self):
		if not self.is_raw_disassembly:
			return self.src_editor.getCurrentMediumLevelILFunction()
		return None

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True



class DiffViewType(ViewType):
	# executed at plugin load time from from ui.py ViewType.registerViewType()
	def __init__(self):
		super(DiffViewType, self).__init__("Diff", "Diff")

	def getPriority(self, data, filename):
		return 1

	# executed when user clicks "Debugger" from dropdown with binary views
	def create(self, data, view_frame):
		return DiffView(view_frame, data)

