import os
import re
import time
import platform
import sys
import traceback
import tempfile

from binaryninja import Architecture, BinaryView, Symbol, SymbolType, Type, Structure, StructureType, FunctionGraphType, \
	LowLevelILOperation, MediumLevelILOperation, core_ui_enabled

if core_ui_enabled():
	try:
		# create the widgets, debugger, etc.
		from .ui import initialize_ui

		initialize_ui()
		have_ui = True
	except (ModuleNotFoundError, ImportError, IndexError) as e:
		have_ui = False
		print(e)
		print("Could not initialize UI, using headless mode only")
else:
	have_ui = False