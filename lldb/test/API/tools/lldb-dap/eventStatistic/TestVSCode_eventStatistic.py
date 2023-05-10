"""
Test lldb-dap terminated event
"""

import dap_server
from lldbsuite.test.decorators import *
from lldbsuite.test.lldbtest import *
from lldbsuite.test import lldbutil
import lldbdap_testcase
import re
import json

class TestDAP_eventStatistic(lldbdap_testcase.DAPTestCaseBase):

    def check_statistics_summary(self, statistics):
        self.assertTrue(statistics['totalDebugInfoByteSize'] > 0)
        self.assertTrue(statistics['totalDebugInfoEnabled'] > 0)
        self.assertTrue(statistics['totalModuleCountHasDebugInfo'] > 0)

        self.assertNotIn('modules', statistics.keys())

    def check_target_summary(self, statistics):
        # lldb-dap debugs one target at a time
        target = json.loads(statistics['targets'])[0]
        self.assertIn('totalSharedLibraryEventHitCount', target)

    @skipIfWindows
    @skipIfRemote
    def test_terminated_event(self):
        """
        Terminated Event
        Now contains the statistics of a debug session:
        metatdata:
            totalDebugInfoByteSize > 0
            totalDebugInfoEnabled > 0
            totalModuleCountHasDebugInfo > 0
            ...
        targetInfo:
            totalBreakpointResolveTime > 0
        breakpoints:
            recognize function breakpoint
            recognize source line breakpoint
        It should contains the breakpoints info: function bp & source line bp
        """

        program_basename = "a.out.stripped"
        program = self.getBuildArtifact(program_basename)
        self.build_and_launch(program)
        # Set breakpoints
        functions = ["foo"]
        breakpoint_ids = self.set_function_breakpoints(functions)
        self.assertEquals(len(breakpoint_ids), len(functions), "expect one breakpoint")
        main_bp_line = line_number("main.cpp", "// main breakpoint 1")
        breakpoint_ids.append(self.set_source_breakpoints("main.cpp", [main_bp_line]))

        self.continue_to_breakpoints(breakpoint_ids)
        self.continue_to_exit()

        statistics = self.dap_server.wait_for_terminated()['statistics']
        self.check_statistics_summary(statistics)
        self.check_target_summary(statistics)

    @skipIfWindows
    @skipIfRemote
    def test_initialized_event(self):
        '''
            Initialized Event
            Now contains the statistics of a debug session:
                totalDebugInfoByteSize > 0
                totalDebugInfoEnabled > 0
                totalModuleCountHasDebugInfo > 0
                ...
        '''

        program_basename = "a.out.stripped"
        program = self.getBuildArtifact(program_basename)
        self.build_and_launch(program)
        statistics = self.dap_server.initialized_event['statistics']
        self.check_statistics_summary(statistics)
        self.continue_to_exit()
