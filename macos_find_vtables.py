#Macos Find Vtables
#@author
#@category _NEW_
#@keybinding
#@menupath
#@toolbar
#@runtime Jython

import sys
import os

# Ensure the directory containing this script is on the path so that
# ghidra_context and vtable_finder can be imported as plain modules.
_script_dir = sourceFile.getParentFile().toString()
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

import ghidra_context
import vtable_finder

# ---------------------------------------------------------------------------
# Initialise context and run scan
# ---------------------------------------------------------------------------

ctx = ghidra_context.GhidraContext(currentProgram, currentLocation, this)

all_vtables, no_string, no_vtable = vtable_finder.find_all_vtables(ctx)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print("")

if no_vtable:
    print("No vtable found (string exists but no vtable detected):")
    for name, failures in no_vtable:
        print("  MISSING  {}".format(name))
        for reason in failures:
            print("           - {}".format(reason))
    print("")

if no_string:
    print("No string found in binary (vtable search skipped):")
    for name in no_string:
        print("  NO STR   {}".format(name))
    print("")

total_slots     = sum(vt["slot_count"]      for vt in all_vtables)
total_undefined = sum(vt["undefined_slots"] for vt in all_vtables)
all_undefined_addrs = set()
for vt in all_vtables:
    all_undefined_addrs.update(vt["undefined_addrs"])

primary_count   = sum(1 for vt in all_vtables if not vt["is_secondary"])
secondary_count = sum(1 for vt in all_vtables if     vt["is_secondary"])

print("Found {} vtable(s) total ({} primary, {} secondary), "
      "{} slots total, {} undefined ({:.1f}%), "
      "{} unique undefined addresses".format(
          len(all_vtables),
          primary_count,
          secondary_count,
          total_slots,
          total_undefined,
          100.0 * total_undefined / total_slots if total_slots > 0 else 0.0,
          len(all_undefined_addrs)))
