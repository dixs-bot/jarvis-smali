import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location("smj",Path(__file__).parents[1]/"main.py")
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def test_signatures():
 assert m.sig(b"dex\\n035\\0")=="DEX_MAGIC"
 assert m.sig(b"PK\\x03\\x04")=="ZIP/JAR_MAGIC"
def test_missing_path():
 assert m.inspect("/unlikely/path/smali-jarvis-not-found")["status"]=="NOT_FOUND"
