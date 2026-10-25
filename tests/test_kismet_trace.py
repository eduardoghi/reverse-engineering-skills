"""Tests for bin/kismet-trace against a small blueprint export built here.

The export imitates what CUE4Parse writes with ReadScriptData set, with an
ExecuteUbergraph function holding two events, the stubs that call it and a
plain function. Run with `python3 -m unittest discover -s tests`.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

KISMET_TRACE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "kismet-trace")
UBER = "ExecuteUbergraph_BP_Door"


def var(name, token="EX_LocalVariable"):
    return {"Token": token, "Variable": {"Type": "BoolProperty", "Name": name}}


def func(name, cls="KismetSystemLibrary"):
    return {"ObjectName": f"Function'{cls}:{name}'", "ObjectPath": "/Script/Engine"}


def call(name, *params, token="EX_FinalFunction"):
    return {"Token": token, "Function": func(name), "Parameters": list(params)}


def string(text):
    return {"Token": "EX_StringConst", "Value": text}


def at(index, statement):
    return dict(statement, StatementIndex=index)


def latent(resume):
    return {"Token": "EX_StructConst", "Struct": {"ObjectName": "ScriptStruct'LatentActionInfo'"},
            "Properties": [{"Token": "EX_SkipOffsetConst", "Value": resume}, {"Token": "EX_IntConst", "Value": 7},
                           {"Token": "EX_NameConst", "Value": UBER}, {"Token": "EX_Self"}]}


def stub(name, offset):
    return {"Type": "Function", "Name": name, "ScriptBytecode": [
        at(0, {"Token": "EX_VirtualFunction", "Function": UBER,
               "Parameters": [{"Token": "EX_IntConst", "Value": offset}]}),
        at(19, {"Token": "EX_Return", "Expression": {"Token": "EX_Nothing"}}),
        at(21, {"Token": "EX_EndOfScript"}),
    ]}


EXPORTS = [
    {"Type": "Function", "Name": UBER, "ScriptBytecode": [
        # OnOpen starts at 0.
        at(0, {"Token": "EX_Let", "Variable": var("Count"), "Expression": {"Token": "EX_IntConst", "Value": 1}}),
        at(10, {"Token": "EX_PushExecutionFlow", "PushingAddress": 40}),
        at(15, {"Token": "EX_JumpIfNot", "CodeOffset": 30, "BooleanExpression": var("bLocked")}),
        at(25, call("PrintString", {"Token": "EX_Self"}, string("locked"))),
        at(28, {"Token": "EX_PopExecutionFlow"}),
        at(30, call("PrintString", {"Token": "EX_Self"}, string("open"))),
        at(35, {"Token": "EX_PopExecutionFlow"}),
        at(40, {"Token": "EX_CallMulticastDelegate", "FunctionName": "OnDoorOpened__DelegateSignature",
                "Delegate": var("OnDoorOpened", "EX_InstanceVariable"), "Parameters": []}),
        at(45, call("Delay", {"Token": "EX_Self"}, {"Token": "EX_FloatConst", "Value": 2.0}, latent(60))),
        at(50, {"Token": "EX_PopExecutionFlow"}),
        # OnClose starts at 55.
        at(55, {"Token": "EX_Jump", "CodeOffset": 70}),
        at(60, call("PrintString", {"Token": "EX_Self"}, string("delay done"))),
        at(63, {"Token": "EX_PopExecutionFlow"}),
        at(70, {"Token": "EX_LetBool", "Variable": var("bClosed", "EX_InstanceVariable"), "Expression": {"Token": "EX_True"}}),
        at(75, {"Token": "EX_PopExecutionFlow"}),
        at(80, {"Token": "EX_Return", "Expression": {"Token": "EX_Nothing"}}),
        at(82, {"Token": "EX_EndOfScript"}),
    ]},
    stub("OnOpen", 0),
    stub("OnClose", 55),
    {"Type": "Function", "Name": "PickSound", "ScriptBytecode": [
        at(0, {"Token": "EX_Let", "Variable": var("Sound"), "Expression": {
            "Token": "EX_SwitchValue", "IndexTerm": var("State"), "EndGotoOffset": 40,
            "Cases": [{"CaseIndexValueTerm": {"Token": "EX_ByteConst", "Value": 0}, "NextOffset": 20,
                       "CaseTerm": string("creak")}],
            "DefaultTerm": string("none")}}),
        at(40, {"Token": "EX_FutureToken", "Payload": 1}),
        at(45, {"Token": "EX_Return", "Expression": var("Sound")}),
        at(50, {"Token": "EX_EndOfScript"}),
    ]},
]


def run(*args):
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable, KISMET_TRACE, *args], capture_output=True, env=env, timeout=60)
    # Windows writes text-mode output with CRLF.
    return (r.returncode, r.stdout.decode("utf-8").replace("\r\n", "\n"),
            r.stderr.decode("utf-8").replace("\r\n", "\n"))


class KismetTraceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = os.path.join(cls.tmp.name, "BP_Door.uasset.json")
        with open(cls.path, "w", encoding="utf-8") as fh:
            json.dump(EXPORTS, fh)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def ok(self, *args):
        code, out, err = run(*args)
        self.assertEqual(code, 0, err)
        return out

    def write(self, name, exports):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(exports, fh)
        return path

    def test_events(self):
        self.assertEqual(self.ok("events", self.path), "       0 OnOpen\n      55 OnClose\n")

    def test_list_marks_entries_and_renders_statements(self):
        out = self.ok("list", self.path)
        for line in ("  ---- entry 0: OnOpen", "  [0] Count = 1", "  [15] if not (bLocked) goto 30",
                     "  [25] PrintString(self, 'locked')",
                     "  [40] OnDoorOpened.Broadcast()", "  ---- entry 55: OnClose", "  [70] bClosed = true",
                     "  [0] Sound = switch(State) {0: 'creak', default: 'none'}"):
            self.assertIn(line, out)

    def test_unknown_token_is_shown_not_dropped(self):
        self.assertIn("  [40] <EX_FutureToken ['Payload']>", self.ok("list", self.path, "PickSound"))

    def test_follow_branches_flow_stack_and_latent_resume(self):
        out = self.ok("follow", self.path, "OnOpen")
        self.assertEqual(out, "\n".join([
            "",
            "######## OnOpen @ 0",
            "-- path from 0",
            "   [0] Count = 1",
            "   [15] if not (bLocked) -> branch 30",
            "   [25] PrintString(self, 'locked')",
            "   [40] OnDoorOpened.Broadcast()",
            f"   [45] Delay(self, 2.0, LatentActionInfo{{60, 7, '{UBER}', self}})",
            "   [50] end",
            "  -- branch from 30",
            "     [30] PrintString(self, 'open')",
            "     (continues as already shown at 40)",
            "  -- resumes later from 60",
            "     [60] PrintString(self, 'delay done')",
            "     [63] end",
            "",
        ]))

    def test_follow_by_part_of_a_name_or_an_offset(self):
        for event in ("Close", "55"):
            out = self.ok("follow", self.path, event)
            self.assertIn("   [70] bClosed = true\n   [75] end", out)

    def test_hide(self):
        out = self.ok("follow", self.path, "OnOpen", "--hide", "PrintString")
        self.assertNotIn("PrintString", out)
        self.assertIn("   [40] OnDoorOpened.Broadcast()", out)

    def test_ambiguous_event(self):
        code, _, err = run("follow", self.path, "On")
        self.assertEqual(code, 1)
        self.assertIn("'On' matches 2 events", err)

    def test_function_without_bytecode_is_skipped(self):
        # CUE4Parse leaves ScriptBytecode out of functions with no code, such as delegate signatures.
        path = self.write("signature.json", EXPORTS + [{"Type": "Function", "Name": "OnDoorOpened__DelegateSignature"}])
        self.assertEqual(self.ok("events", path), "       0 OnOpen\n      55 OnClose\n")

    def test_jump_to_an_offset_that_is_not_a_statement(self):
        for target, shown in ((71, "71"), ("\x1b[2J", "'\\x1b[2J'"), ([1], "[1]")):
            with self.subTest(target=target):
                exports = copy.deepcopy(EXPORTS)
                jump = next(s for s in exports[0]["ScriptBytecode"] if s["StatementIndex"] == 55)
                jump["CodeOffset"] = target
                out = self.ok("follow", self.write("badjump.json", exports), "OnClose")
                self.assertIn(f"   {shown} is not a statement offset, not followed\n", out)
                self.assertNotIn("\x1b", out)

    def test_branch_target_from_the_file_is_escaped(self):
        exports = copy.deepcopy(EXPORTS)
        branch = next(s for s in exports[0]["ScriptBytecode"] if s["StatementIndex"] == 15)
        branch["CodeOffset"] = "\x1b]0;x\x07"
        out = self.ok("follow", self.write("badbranch.json", exports), "OnOpen")
        self.assertNotIn("\x1b", out)
        self.assertIn("-> branch '\\x1b]0;x\\x07'", out)

    def test_event_names_in_errors_are_escaped(self):
        path = self.write("esc.json", EXPORTS + [stub("On\x1b[31mRed", 0)])
        code, _, err = run("follow", path, "On")
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", err)
        self.assertIn("On\\x1b[31mRed", err)

    def test_export_without_bytecode(self):
        path = os.path.join(self.tmp.name, "nobytecode.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump([{"Type": "Function", "Name": "F"}], fh)
        code, _, err = run("list", path)
        self.assertEqual(code, 1)
        self.assertIn("ReadScriptData", err)


if __name__ == "__main__":
    unittest.main()
