"""
The test suit for the MonitorCommand class
"""
#pylint: disable=protected-access,missing-function-docstring,consider-using-f-string,invalid-name,line-too-long,missing-class-docstring
import logging
import importlib
from unittest import TestCase
from dwgdbserver.dwgdbserver import MonitorCommand


logging.basicConfig(level=logging.CRITICAL)

class TestMonitorCommand(TestCase):

    def setUp(self):
        self.mo = MonitorCommand(False, False)

    def test_dispatch_ambigious(self):
        self.assertEqual(self.mo.dispatch(["ver"]), ("", "Ambiguous 'monitor' command"))

    def test_dispatch_unknown(self):
        self.assertEqual(self.mo.dispatch(["XXX"]), ("", "Unknown 'monitor' command"))

    def test_dispatch_breakpoints(self):
        self.mo._onlyhwbps = False
        self.mo._onlyswbps = False
        self.assertEqual(self.mo.dispatch(["break"]), ("", "All breakpoints are allowed"))
        self.mo._onlyhwbps = True
        self.mo._onlyswbps = False
        self.assertEqual(self.mo.dispatch(["break"]), ("", "Only hardware breakpoints are allowed"))
        self.mo._onlyhwbps = False
        self.mo._onlyswbps = True
        self.assertEqual(self.mo.dispatch(["break"]), ("", "Only software breakpoints are allowed"))
        self.mo._onlyhwbps = True
        self.mo._onlyswbps = True
        self.assertEqual(self.mo.dispatch(["break"]), ("", "Internal confusion: No breakpoints are allowed"))
        self.assertEqual(self.mo.dispatch(["break", "all"]), ("", "All breakpoints are now allowed"))
        self.assertEqual(self.mo._onlyhwbps, False)
        self.assertEqual(self.mo._onlyswbps, False)
        self.assertEqual(self.mo.dispatch(["break", "hardware"]), ("", "Only hardware breakpoints are now allowed"))
        self.assertEqual(self.mo._onlyhwbps, True)
        self.assertEqual(self.mo._onlyswbps, False)
        self.assertEqual(self.mo.dispatch(["break", "software"]), ("", "Only software breakpoints are now allowed"))
        self.assertEqual(self.mo._onlyhwbps, False)
        self.assertEqual(self.mo._onlyswbps, True)
        self.assertEqual(self.mo.dispatch(["break", "X"]), ("", "Unknown 'monitor' command"))

    def test_dispatch_Cache(self):
        self.mo._cache = False
        self.assertEqual(self.mo.dispatch(["caching", "enable"]), ("", "Flash memory will be cached"))
        self.assertEqual(self.mo._cache, True)
        self.assertEqual(self.mo.dispatch(["ca", ""]), ("", "Flash memory will be cached"))
        self.assertEqual(self.mo.dispatch(["caching", "dis"]), ("", "Flash memory will not be cached"))
        self.assertEqual(self.mo._cache, False)
        self.assertEqual(self.mo.dispatch(["ca", ""]), ("", "Flash memory will not be cached"))

    def test_dispatch_debugWIRE(self):
        self.mo._dw_mode_active = False
        self.assertEqual(self.mo.dispatch(["d", ""]), ("", "debugWIRE mode is disabled"))
        self.mo._dw_mode_active = True
        self.assertEqual(self.mo.dispatch(["debugwire"]), ("", "debugWIRE mode is enabled"))
        self.mo._dw_mode_active = False
        self.assertEqual(self.mo.dispatch(["debug", "e"]), ("dwon", "debugWIRE mode is now enabled"))
        self.assertFalse(self.mo._dw_mode_active) # The enable command does NOT change the value of the state var!
        self.mo._dw_mode_active = True
        self.assertEqual(self.mo.dispatch(["debug", "dis"]), ("dwoff", "debugWIRE mode is now disabled"))
        self.assertFalse(self.mo._dw_mode_active)
        self.mo._dw_activated_once = True
        self.assertEqual(self.mo.dispatch(["debug", "enable"]),
                             ("", "Cannot reactivate debugWIRE\nYou have to exit and restart the debugger"))
        self.assertFalse(self.mo._dw_mode_active)
        self.assertTrue(self.mo._dw_activated_once)

    def test_dispatch_flashVerify(self):
        self.assertTrue(self.mo._verify)
        self.assertEqual(self.mo.dispatch(['veri']), ("", "Always verifying that load operations are successful"))
        self.assertEqual(self.mo.dispatch(['verify', 'disable']), ("", "Load operations are not verified"))
        self.assertFalse(self.mo._verify)
        self.assertEqual(self.mo.dispatch(['veri', 'e']), ("", "Always verifying that load operations are successful"))
        self.assertTrue(self.mo._verify)
        self.assertEqual(self.mo.dispatch(['veri', 'ex']), ("", "Unknown 'monitor' command"))
        self.assertEqual(self.mo.dispatch(['ver']), ("", "Ambiguous 'monitor' command"))


    def test_dispatch_help(self):
        self.assertTrue(len(self.mo.dispatch(['help'])[1]) > 1000)
        self.assertTrue(len(self.mo.dispatch([])[1]) > 1000)

    def test_dispatch_info(self):
        try:
            importlib.metadata.version("dwgdbserver")
        except importlib.metadata.PackageNotFoundError:
            return
        self.assertTrue(len(self.mo.dispatch(['info'])[1]) > 50)
        self.assertEqual(self.mo.dispatch(['info'])[0], 'info')

    def test_dispatch_load(self):
        self.assertTrue(self.mo._fastload)
        self.assertEqual(self.mo.dispatch(['load']), ("", "Reading before writing when loading"))
        self.assertEqual(self.mo.dispatch(['load', 'writeonly']),  ("", "No reading before writing when loading"))
        self.assertFalse(self.mo._fastload)
        self.assertEqual(self.mo.dispatch(['load', 'read']),  ("", "Reading before writing when loading"))
        self.assertTrue(self.mo._fastload)

    def test_dispatch_noload(self):
        self.assertFalse(self.mo._noload)
        self.assertEqual(self.mo.dispatch(['onlyloaded', 'dis']), ("", "Execution without prior 'load' command is possible"))
        self.assertTrue(self.mo._noload)
        self.assertEqual(self.mo.dispatch(['only', 'enable']), ("",  "Execution without prior 'load' command is impossible"))
        self.assertFalse(self.mo._noload)

    def test_dispatch_range(self):
        self.assertTrue(self.mo._range)
        self.assertEqual(self.mo.dispatch(['rangestepping', 'disable']), ("", "Range stepping is disabled"))
        self.assertFalse(self.mo._range)
        self.assertEqual(self.mo.dispatch(['range']), ("", "Range stepping is disabled"))
        self.assertEqual(self.mo.dispatch(['rangestepping', 'enable']), ("", "Range stepping is enabled"))
        self.assertTrue(self.mo._range)


    def test_dispatch_reset(self):
        self.mo._dw_mode_active = False
        self.assertEqual(self.mo.dispatch(['reset', 'halt']), ("","Enable debugWIRE mode first"))
        self.mo._dw_mode_active = True
        self.assertEqual(self.mo.dispatch(['res']), ("reset", "MCU has been reset"))

    def test_dispatch_singlestep(self):
        self.assertTrue(self.mo._safe)
        self.assertEqual(self.mo.dispatch(['singlestep', 'interruptible']), ("", "Single-stepping is interruptible"))
        self.assertFalse(self.mo._safe)
        self.assertEqual(self.mo.dispatch(['singlestep']), ("", "Single-stepping is interruptible"))
        self.assertEqual(self.mo.dispatch(['s', 's']), ("", "Single-stepping is interrupt-safe"))
        self.assertTrue(self.mo._safe)

    def test_dispatch_timers(self):
        self.assertTrue(self.mo._timersfreeze)
        self.assertEqual(self.mo.dispatch(['timers', 'run']), (1, "Timers will run when execution is stopped"))
        self.assertFalse(self.mo._timersfreeze)
        self.assertEqual(self.mo.dispatch(['timers', 'freeze']), (0, "Timers are frozen when execution is stopped"))
        self.assertTrue(self.mo._timersfreeze)
        self.assertEqual(self.mo.dispatch(['timers']), (0, "Timers are frozen when execution is stopped"))

    def test_dispatch_version(self):
        try:
            importlib.metadata.version("dwgdbserver")
        except importlib.metadata.PackageNotFoundError:
            return
        self.assertEqual(self.mo.dispatch(['version']), ("", "dw-gdbserver {}".format(importlib.metadata.version("dwgdbserver"))))
