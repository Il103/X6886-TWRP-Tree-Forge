from __future__ import annotations
import importlib.util,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location(name.removesuffix('.py'),ROOT/'scripts'/name);assert spec and spec.loader
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
collect=load('collect_a16.py');hydrate=load('hydrate_runtime_refs.py');harden=load('harden_tree.py')
class Recovery14HardeningTest(unittest.TestCase):
 def test_android16_bare_logical_fstab(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'fstab.mt6789';p.write_text('system /system erofs ro wait,slotselect,logical,first_stage_mount\n/dev/block/by-name/userdata /data f2fs noatime wait,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption\n')
   rows=collect.parse_fstab_a16(p);self.assertEqual('system',rows[0]['device']);self.assertEqual('android',rows[0]['style']);self.assertIn('logical',rows[0]['fs_mgr_flags'])
 def test_trustonic_runtime_references(self):
  text='service mobicore /vendor/bin/mcDriverDaemon --P1 /mnt/vendor/persist/mcRegistry\\\n    -r /vendor/app/mcRegistry/keymint.drbin\\\n    -r /apex/com.mediatek.oemcrypto/firmware/tee/widevine.drbin\n'
  required,optional,services,directories=hydrate.parse_rc(text)
  self.assertIn('/vendor/bin/mcDriverDaemon',required);self.assertIn('/vendor/app/mcRegistry/keymint.drbin',required);self.assertIn('/apex/com.mediatek.oemcrypto/firmware/tee/widevine.drbin',optional);self.assertIn('/mnt/vendor/persist/mcRegistry',directories);self.assertIn('/vendor/bin/mcDriverDaemon',services)
 def test_stock_module_bytes_and_order(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'modules.load.recovery';raw=b'a.ko\nb.ko';p.write_bytes(raw);self.assertEqual(['a.ko','b.ko'],harden.modules(p));self.assertEqual(raw,p.read_bytes())
if __name__=='__main__':unittest.main()
