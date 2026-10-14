"""Synthetic/offline unit tests ONLY: no WinDbg or ScreenWings process executed."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load_module(filename):
    path=ROOT/"tools"/filename
    spec=importlib.util.spec_from_file_location(filename.replace(".py",""),path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

generator=load_module("make_p0_av_proof.py")
triage=load_module("triage_p0_windbg.py")

class P0ProofTest(unittest.TestCase):
    def test_rejects_invalid_runtime_base(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,"Invalid"):
                generator.generate(0,pathlib.Path(d))

    def test_rebase_and_exact_expected_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            output=pathlib.Path(d)
            m=generator.generate(0x500000,output)
            last=m["phases"]["pointer_path"][-1]
            self.assertEqual(last["runtime_va"],"0x63d2ef")
            self.assertEqual(last["expected_bytes"],"8b3f")
            contents=(output/"p0_pointer_path.windbgcmd").read_text()
            self.assertIn("db 0x0063D2EF L2",contents)
            self.assertIn("EXPECTED_P0_SECOND_EDI_DEREF",contents)
            self.assertNotIn("ba e 1 0x0063D2EF \"g\"",contents)

    def test_chance_events_and_manual_gn(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)
            generator.generate(0x400000,path)
            text=(path/"p0_av_only.windbgcmd").read_text()
            self.assertIn('sxe -c ".echo P0_FIRST_CHANCE_AV;',text)
            self.assertIn('-c2 ".echo P0_SECOND_CHANCE_AV;',text)
            self.assertIn("gn",text)
            self.assertNotIn("\ng\n",text)

    def test_synthetic_av_not_handler_proof(self):
        fake=("P0_FIRST_CHANCE_AV\n"
              "eip=0053d2ef esp=00abc000\n"
              "ExceptionAddress: 0053d2ef\n"
              "ExceptionCode: c0000005\n"
              "Attempt to read from address 00000018\n"
              "P0_SECOND_CHANCE_AV\n"
              "ExceptionCode: c0000005\n")
        r=triage.summarize(fake,0x400000)
        self.assertTrue(r["supports_native_first_chance_at_model_cutoff"])
        self.assertEqual(r["second_chance_access_violations"],1)
        self.assertFalse(r["proves_handler_caught_this_exact_fault"])

    def test_empty_log_is_inconclusive(self):
        r=triage.summarize("",0x400000)
        self.assertFalse(r["has_event_markers"])
        self.assertIsNotNone(r["no_event_warning"])

if __name__=="__main__":
    unittest.main()
