from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

from binaryninja import Endianness, BinaryView
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler

from . import widget
from . import DiffView

class DebugStackModel(QAbstractItemModel):
	def __init__(self, parent, bv):
		QAbstractItemModel.__init__(self, parent)
		self.bv = bv
		self.columns = ["Offset", "Value", "References", "Address"]
		self.rows = []
		self.update_rows(None)

	def update_rows(self, new_rows):
		self.beginResetModel()

		old_values = {}
		for info in self.rows:
			old_values[info['offset']] = info['value']

		self.rows = []
		if new_rows is None:
			self.endResetModel()
			return

		# Fill self.rows
		for info in new_rows:
			info['state'] = 'unchanged' if old_values.get(info['offset'], -1) == info['value'] else 'updated'
			self.rows.append(info)

		self.endResetModel()

	def index(self, row, column, parent):
		if parent.isValid() or column > len(self.columns) or row >= len(self.rows):
			return QModelIndex()
		return self.createIndex(row, column)

	def parent(self, child):
		return QModelIndex()

	def hasChildren(self, parent):
		return False

	def rowCount(self, parent):
		if parent.isValid():
			return 0
		return len(self.rows)

	def columnCount(self, parent):
		return len(self.columns)

	def flags(self, index):
		f = super().flags(index)
		if self.columns[index.column()] == "Value":
			f |= Qt.ItemIsEditable
		return f

	def headerData(self, section, orientation, role):
		if role != Qt.DisplayRole:
			return None
		if orientation == Qt.Vertical:
			return None
		return self.columns[section]


class DebugStackItemDelegate(QItemDelegate):
	def __init__(self, parent):
		QItemDelegate.__init__(self, parent)

		self.font = binaryninjaui.getMonospaceFont(parent)
		self.font.setKerning(False)
		self.baseline = QFontMetricsF(self.font).ascent()
		self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
		self.char_height = QFontMetricsF(self.font).height()
		self.char_offset = binaryninjaui.getFontVerticalOffset()

		self.expected_char_widths = [10, 20, 30, 20]

	def sizeHint(self, option, idx):
		return QSize(self.char_width * self.expected_char_widths[idx.column()] + 4, self.char_height)

	def paint(self, painter, option, idx):
		# Draw background highlight in theme style
		selected = option.state & QStyle.State_Selected != 0
		if selected:
			painter.setBrush(binaryninjaui.getThemeColor(binaryninjaui.SelectionColor))
		else:
			painter.setBrush(option.backgroundBrush)
		painter.setPen(Qt.NoPen)
		painter.drawRect(option.rect)

		text = idx.data()
		state = idx.data(Qt.UserRole)

		# Draw text depending on state
		painter.setFont(self.font)
		if state == 'updated':
			painter.setPen(option.palette.color(QPalette.Highlight).rgba())
		elif state == 'modified':
			painter.setPen(binaryninjaui.getThemeColor(binaryninjaui.OrangeStandardHighlightColor).rgba())
		else:
			painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))

	def setEditorData(self, editor, idx):
		if idx.column() == 1:
			data = idx.data()
			editor.setText(data)


class DiffDestWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data
		self.destination_editor = None
		self.dv = None

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugStackModel(self.table, data)
		self.table.setModel(self.model)

		self.item_delegate = DebugStackItemDelegate(self)
		self.table.setItemDelegate(self.item_delegate)

		# self.table.setSortingEnabled(True)
		self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

		self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
		self.table.verticalHeader().setVisible(False)

		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

		self.table.resizeColumnsToContents()
		self.table.resizeRowsToContents()

		for i in range(len(self.model.columns)):
			self.table.setColumnWidth(i, self.item_delegate.sizeHint(self.table.viewOptions(), self.model.index(-1, i, QModelIndex())).width())

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		# linear_views = self.getParentWindow().findChildren(binaryninjaui.LinearView)
		if self.dv is None:
			dvs = self.getParentWindow().findChildren(binaryninjaui.View)
			for dv in dvs:
				if isinstance(dv, DiffView.DiffView):
					self.dv = dv

		if self.dv is not None:
			self.dv.navigate(offset)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

