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
 def test_trustonic_persist_mount_generation(self):
  uncovered={'crypto':{'runtime_references':{'required_directories':['/mnt/vendor/persist/mcRegistry']}},'partitions':{'selected_entries':[{'mount_point':'/data'},{'mount_point':'/metadata'}],'fstabs':[{'entries':[{'device':'/dev/block/by-name/persist','mount_point':'/mnt/vendor/persist','fs_type':'ext4','raw':'/dev/block/by-name/persist /mnt/vendor/persist ext4 noatime wait'}]}]}}
  mounts=harden.compute_security_mounts(uncovered)
  self.assertEqual(1,len(mounts));self.assertEqual('/mnt/vendor/persist',mounts[0]['mount_point']);self.assertEqual('/dev/block/by-name/persist',mounts[0]['device']);self.assertEqual('ext4',mounts[0]['fs_type'])
  covered={'crypto':{'runtime_references':{'required_directories':['/mnt/vendor/persist/mcRegistry']}},'partitions':{'selected_entries':[{'mount_point':'/mnt/vendor/persist'}],'fstabs':[]}}
  self.assertEqual([],harden.compute_security_mounts(covered))
 def test_audit_accepts_generated_persist_mount(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);dump=root/'dump';tree=root/'tree';mods=['clk-mt6789.ko','panel_x6886.ko','ufs-mediatek-mod.ko','mcDrvModule.ko','rpmb.ko','musb_main.ko','goodix_touch.ko']
   (dump/'vendor_boot/ramdisk/lib/modules').mkdir(parents=True);(dump/'vendor_boot/recovery_ramdisk').mkdir(parents=True)
   raw='\n'.join(mods).encode();(dump/'vendor_boot/ramdisk/lib/modules/modules.load.recovery').write_bytes(raw)
   for n in mods:(dump/'vendor_boot/ramdisk/lib/modules'/n).write_bytes(b'ko')
   fstab='system /system erofs ro wait,slotselect,logical,first_stage_mount\n/dev/block/by-name/metadata /metadata f2fs noatime wait,check,formattable\n/dev/block/by-name/userdata /data f2fs noatime wait,check,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption\n'
   (dump/'vendor_boot/ramdisk/first_stage_ramdisk').mkdir(parents=True);(dump/'vendor_boot/ramdisk/first_stage_ramdisk/fstab.mt6789').write_text(fstab)
   (dump/'vendor_boot/recovery_ramdisk/system/etc').mkdir(parents=True);(dump/'vendor_boot/recovery_ramdisk/system/etc/recovery.fstab').write_text(fstab)
   rc='service mobicore /vendor/bin/mcDriverDaemon --P1 /mnt/vendor/persist/mcRegistry\n    class core\nservice vendor.keymint-trustonic /vendor/bin/hw/keymint.trustonic\n    class early_hal\nservice vendor.gatekeeper-default /vendor/bin/hw/gatekeeper.trustonic\n    class early_hal\n'
   for rel,txt in {'vendor/etc/init/trustonic.rc':rc}.items():
    (dump/rel.split('/')[0]).mkdir(exist_ok=True);(dump/rel).parent.mkdir(parents=True,exist_ok=True);(dump/rel).write_text(txt);(tree/('recovery/root/'+rel)).parent.mkdir(parents=True,exist_ok=True);(tree/('recovery/root/'+rel)).write_text(txt)
   for b in ('vendor/bin/mcDriverDaemon','vendor/bin/hw/keymint.trustonic','vendor/bin/hw/gatekeeper.trustonic'):
    (dump/b).parent.mkdir(parents=True,exist_ok=True);(dump/b).write_bytes(b'bin');(tree/('recovery/root/'+b)).parent.mkdir(parents=True,exist_ok=True);(tree/('recovery/root/'+b)).write_bytes(b'bin')
   (tree/'prebuilt/modules').mkdir(parents=True)
   for n in mods:(tree/'prebuilt/modules'/n).write_bytes(b'ko')
   (tree/'prebuilt/modules/modules.load.recovery').write_bytes(b'wrong\n')
   (tree/'BoardConfig.mk').write_text('TARGET_BOARD_PLATFORM := mt6789\nTW_LOAD_VENDOR_BOOT_MODULES := true\n# KeyMint/Gatekeeper services and DT_NEEDED closure are copied from stock A16.\n')
   (tree/'system.prop').write_text('ro.product.device=x6886\n')
   (tree/'recovery/root/system/etc').mkdir(parents=True,exist_ok=True);(tree/'recovery/root/system/etc/recovery.fstab').write_text(fstab+'/system_root auto /dev/block/mapper/system flags=slotselect;logical\n')
   (tree/'recovery/root/init.recovery.mt6789.rc').parent.mkdir(parents=True,exist_ok=True);(tree/'recovery/root/init.recovery.mt6789.rc').write_text('import /init.recovery.project.rc\n')
   (tree/'_provenance').mkdir(parents=True,exist_ok=True);(tree/'_provenance/copied-files.json').write_text('{"old_tree_used": false, "copied_from_android16_dump": [{"from": "vendor_boot/ramdisk/lib/modules/modules.load.recovery", "to": "prebuilt/modules/modules.load.recovery"}]}')
   facts={'identity':{'platform':{'value':'mt6789'}},'partitions':{'selected_fstab':'vendor_boot/recovery_ramdisk/system/etc/recovery.fstab','selected_entries':[{'mount_point':'/data'},{'mount_point':'/metadata'},{'mount_point':'/system'}],'fstabs':[{'entries':[{'device':'/dev/block/by-name/persist','mount_point':'/mnt/vendor/persist','fs_type':'ext4','raw':'persist evidence'}]}]},'kernel':{'modules':{'recovery_load_file':'vendor_boot/ramdisk/lib/modules/modules.load.recovery','recovery_load_order':mods,'load_files':[{'path':'vendor_boot/ramdisk/lib/modules/modules.load.recovery','modules':mods}]}},'crypto':{'copy_files':[{'path':'vendor/etc/init/trustonic.rc','role':'security-init-runtime'}],'runtime_references':{'resolved':{'/vendor/bin/mcDriverDaemon':'vendor/bin/mcDriverDaemon'},'unresolved':[],'optional_unresolved':[],'required_directories':['/mnt/vendor/persist/mcRegistry']}},'security_properties':{}}
   fp=root/'facts.json';import json as j;fp.write_text(j.dumps(facts))
   harden.apply(dump,fp,tree)
   project=(tree/'recovery/root/init.recovery.project.rc').read_text()
   self.assertIn('import /vendor/etc/init/trustonic.rc',project);self.assertIn('mount ext4 /dev/block/by-name/persist /mnt/vendor/persist rw',project)
   self.assertEqual(raw,(tree/'prebuilt/modules/modules.load.recovery').read_bytes())
   result=harden.Audit(dump,facts,tree).run();fails=[c for c in result['checks'] if c['status']=='FAIL']
   self.assertEqual([],fails,fails);self.assertEqual('RECOVERY14_STATIC_COMPLETE',result['readiness'])
if __name__=='__main__':unittest.main()
