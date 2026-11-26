import ida_auto
import ida_hexrays
import idautils
import idc

# Tunggu auto-analysis IDA (parsing .gopclntab) selesai sepenuhnya
ida_auto.auto_wait()

TARGET_KEYWORDS = ("main_", "main.", "idiom", "XorProcessor")

with open("dump_go_idioms.c", "w", encoding="utf-8") as f:
  for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if any(k in name for k in TARGET_KEYWORDS):
      try:
        cfunc = ida_hexrays.decompile(ea)
        f.write(f"// === {name} @ {hex(ea)} ===\n")
        f.write(str(cfunc) + "\n\n")
      except Exception as e:
        f.write(f"// FAILED {name}: {e}\n\n")

print("[+] Dump selesai -> dump_go_idioms.c")
