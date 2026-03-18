#Macos Apply Vtables
#@author
#@category _NEW_
#@keybinding
#@menupath
#@toolbar
#@runtime jython

import sys

# Ensure sibling modules are importable.
_script_dir = sourceFile.getParentFile().toString()
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

import ghidra_context
import vtable_finder
import vtable_applier

# ---------------------------------------------------------------------------
# Initialise context
# ---------------------------------------------------------------------------

ctx = ghidra_context.GhidraContext(currentProgram, currentLocation, this)

# ---------------------------------------------------------------------------
# Phase 0: Discover vtables (read-only)
# ---------------------------------------------------------------------------

all_vtables, no_string, no_vtable = vtable_finder.find_all_vtables(ctx)

if not all_vtables:
    print("No vtables found -- nothing to apply.")
else:
    # -----------------------------------------------------------------------
    # Phases 1-3: Apply (all writes inside a single transaction)
    # -----------------------------------------------------------------------
    tx = currentProgram.startTransaction("Apply vtables")
    try:
        class_map = vtable_applier.apply_all(ctx, all_vtables)
        currentProgram.endTransaction(tx, True)
        print("Transaction committed.")
    except Exception as e:
        currentProgram.endTransaction(tx, False)
        print("Transaction rolled back due to error: {}".format(e))
        raise

    # -----------------------------------------------------------------------
    # Final summary
    # -----------------------------------------------------------------------
    print("")
    print("Classes created/reused: {}".format(len(class_map)))

    if no_vtable:
        print("")
        print("No vtable found (string exists but no vtable detected):")
        for name, failures in no_vtable:
            print("  MISSING  {}".format(name))
            for reason in failures:
                print("           - {}".format(reason))

    if no_string:
        print("")
        print("No string found in binary (vtable search skipped):")
        for name in no_string:
            print("  NO STR   {}".format(name))
