from PySide2 import QtCore, QtGui
from PySide2.QtWidgets import QLineEdit, QToolBar, QMenu, QAction
from binaryninja import BinaryView
import os

from .. import binjaplug


def load_icon(fname_icon):
	path_this_file = os.path.abspath(__file__)
	path_this_dir = os.path.dirname(path_this_file)
	path_icons = os.path.join(path_this_dir, '..', 'media', 'icons')
	path_icon = os.path.join(path_icons, fname_icon)

	pixmap = QtGui.QPixmap(path_icon)

	#pixmap.fill(QtGui.QColor('red'))
	#pixmap.setMask(pixmap.createMaskFromColor(QtGui.QColor('black'), QtGui.Qt.MaskOutColor))

	icon = QtGui.QIcon()
	icon.addPixmap(pixmap, QtGui.QIcon.Normal)
	icon.addPixmap(pixmap, QtGui.QIcon.Disabled)

	return icon

class DebugControlsWidget(QToolBar):
	def __init__(self, parent, name, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		QToolBar.__init__(self, parent)

		# TODO: Is there a cleaner way to do this?
		self.setStyleSheet("""
		QToolButton{padding: 4px 14px 4px 14px; font-size: 14pt;}
		QToolButton:disabled{color: palette(alternate-base)}
		""")

		self.actionRun = QAction("Diff", self)
		self.actionRun.triggered.connect(lambda: self.perform_run())
		self.actionRun.setIcon(load_icon('run.svg'))

		self.actionOpenFile = QAction("Open File", self)
		self.actionOpenFile.triggered.connect(lambda: self.perform_restart())
		self.actionOpenFile.setIcon(load_icon('restart.svg'))

		# session control menu
		self.controlMenu = QMenu("Process Control", self)
		self.controlMenu.addAction(self.actionRun)
		self.controlMenu.addSeparator()
		self.controlMenu.addAction(self.actionOpenFile)

		self.editStatus = QLineEdit('INACTIVE', self)
		self.editStatus.setReadOnly(True)
		self.editStatus.setAlignment(QtCore.Qt.AlignCenter)
		self.addWidget(self.editStatus)


	def __del__(self):
		# TODO: Move this elsewhere
		# This widget is tasked with cleaning up the state after the view is closed
		# binjaplug.delete_state(self.bv)
		pass


	# -------------------------------------------------------------------------
	# Control state setters
	# -------------------------------------------------------------------------

	def set_actions_enabled(self, **kwargs):
		def enable_step_into(e):
			self.actionStepIntoAsm.setEnabled(e)
			self.actionStepIntoIL.setEnabled(e)

		def enable_step_over(e):
			self.actionStepOverAsm.setEnabled(e)
			self.actionStepOverIL.setEnabled(e)

		def enable_starting(e):
			self.actionRun.setEnabled(e and self.can_exec())
			self.actionAttach.setEnabled(e and self.can_connect())

		def enable_stopping(e):
			self.actionOpenFile.setEnabled(e)
			self.actionQuit.setEnabled(e)
			self.actionDetach.setEnabled(e)

		def enable_stepping(e):
			self.actionStepIntoAsm.setEnabled(e)
			self.actionStepIntoIL.setEnabled(e)
			self.actionStepOverAsm.setEnabled(e)
			self.actionStepOverIL.setEnabled(e)
			self.actionStepReturn.setEnabled(e)

		actions = {
			"Diff": lambda e: self.actionRun.setEnabled(e),
			"Restart": lambda e: self.actionOpenFile.setEnabled(e),
			"Quit": lambda e: self.actionQuit.setEnabled(e),
			"Attach": lambda e: self.actionAttach.setEnabled(e),
			"Detach": lambda e: self.actionDetach.setEnabled(e),
			"Pause": lambda e: self.actionPause.setEnabled(e),
			"Resume": lambda e: self.actionResume.setEnabled(e),
			"StepInto": enable_step_into,
			"StepOver": enable_step_over,
			"StepReturn": lambda e: self.actionStepReturn.setEnabled(e),
			"Threads": lambda e: self.btnThreads.setEnabled(e),
			"Starting": enable_starting,
			"Stopping": enable_stopping,
			"Stepping": enable_stepping,
		}
		for (action, enabled) in kwargs.items():
			actions[action](enabled)

	def set_default_process_action(self, action):
		actions = {
			"Diff": self.actionRun,
			"Restart": self.actionOpenFile,
			"Quit": self.actionQuit,
			"Attach": self.actionAttach,
			"Detach": self.actionDetach,
		}
		self.btnControl.setDefaultAction(actions[action])

	def set_resume_pause_action(self, action):
		lookup = {'Resume':self.actionResume, 'Pause':self.actionPause}
		self.btnPauseResume.setDefaultAction(lookup[action])

	def set_thread_list(self, threads):
		def select_thread_fn(tid):
			def select_thread(tid):
				stateObj = binjaplug.get_state(self.bv)
				if stateObj.connected and not stateObj.running:
					stateObj.threads.current = tid
					stateObj.ui.context_display()
					stateObj.ui.on_step()
				else:
					print('cannot set thread in current state')

			return lambda: select_thread(tid)

		self.threadMenu.clear()
		if len(threads) > 0:
			for thread in threads:
				item_name = "Thread {} at {}".format(thread['tid'], hex(thread['ip']))
				action = self.threadMenu.addAction(item_name, select_thread_fn(thread['tid']))
				if thread['selected']:
					self.btnThreads.setDefaultAction(action)
		else:
			defaultThreadAction = self.threadMenu.addAction("Thread List")
			defaultThreadAction.setEnabled(False)
			self.btnThreads.setDefaultAction(defaultThreadAction)

	# -------------------------------------------------------------------------
	# State handling
	# -------------------------------------------------------------------------

	def state_starting(self, msg=None):
		self.editStatus.setText(msg or 'INACTIVE')
		self.set_actions_enabled(Starting=False, Stopping=False, Stepping=False, Pause=False, Resume=False, Threads=False)
		self.set_default_process_action("Attach" if self.can_connect() else "Diff")
		self.set_thread_list([])
		self.set_resume_pause_action("Pause")

	def state_inactive(self, msg=None):
		self.editStatus.setText(msg or 'INACTIVE')
		self.set_actions_enabled(Starting=True, Stopping=False, Stepping=False, Pause=False, Resume=False, Threads=False)
		self.set_default_process_action("Attach" if self.can_connect() else "Diff")
		self.set_thread_list([])
		self.set_resume_pause_action("Pause")

	def state_stopped(self, msg=None):
		self.editStatus.setText(msg or 'STOPPED')
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=True, Pause=True, Resume=True, Threads=True)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Resume")

	def state_stopped_extern(self, msg=None):
		self.editStatus.setText(msg or 'STOPPED')
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=True, StepReturn=False, Pause=True, Resume=True, Threads=True)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Resume")

	def state_running(self, msg=None):
		self.editStatus.setText(msg or 'RUNNING')
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=False, Pause=True, Resume=False, Threads=False)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Pause")

	def state_busy(self, msg=None):
		self.editStatus.setText(msg or 'RUNNING')
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=False, Pause=True, Resume=False, Threads=False)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Pause")

	def state_error(self, msg=None):
		self.editStatus.setText(msg or 'ERROR')
		self.set_actions_enabled(Starting=True, Stopping=False, Pause=False, Resume=False, Stepping=False, Threads=False)
		self.set_default_process_action("Attach" if self.can_connect() else "Diff")
		self.set_thread_list([])
		self.set_resume_pause_action("Resume")
