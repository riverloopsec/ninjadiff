from PySide6 import QtCore
from PySide6.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide6.QtGui import QPalette, QFontMetricsF
from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

from binaryninja import Endianness, BinaryView
import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler

from . import widget
from . import DiffView


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


		# self.table.setSortingEnabled(True)
		self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

		self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
		self.table.verticalHeader().setVisible(False)

		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

		self.table.resizeColumnsToContents()
		self.table.resizeRowsToContents()

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

