from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit
from PySide2.QtGui import QDesktopServices
from binaryninja.plugin import PluginCommand
from binaryninja import Endianness, HighlightStandardColor, execute_on_main_thread, execute_on_main_thread_and_wait, LowLevelILOperation, BinaryReader
from binaryninja.settings import Settings
from binaryninja.log import log_warn, log_error, log_debug
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType, ViewFrame
from .dockwidgets import DiffWidget, DiffView, widget
from . import binjaplug
import datetime
import traceback
import os
import pathlib

def cb_diff(bv):
    def switch_view():
        dh = DockHandler.getActiveDockHandler()
        vf = dh.getViewFrame()
        vf.setViewType('Diff:' + bv.view_type)

    execute_on_main_thread_and_wait(switch_view)


def initialize_ui():
    widget.register_dockwidget(DiffWidget.DiffDestWidget, "Diff", Qt.LeftDockWidgetArea, Qt.Vertical, False)

    PluginCommand.register("Diff\\Run", "Select file to diff", cb_diff)

    ViewType.registerViewType(DiffView.DiffViewType())