from PySide6.QtCore import Qt
from binaryninja.plugin import PluginCommand
from binaryninja import execute_on_main_thread_and_wait
from binaryninjaui import DockHandler, ViewType
from .dockwidgets import DiffWidget, DiffView, widget


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