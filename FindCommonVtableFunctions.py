#Find functions with the same name appearing at the same vtable offset across multiple classes
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


# For each vtable offset where 2+ classes have an identified function name (e.g. 'save'),
# prints ALL classes at that offset - including ones still named 'virt_meth_...' etc.
# Those unidentified entries are the ones likely needing to be renamed.
 
import re
from ghidra.program.database.data import StructureDB, PointerDB
from ExportASM import GhidraContext
 
try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False
 
if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
 
 
entity_names = [
    "BFEntity",
    "BFUnit",
    "BFOverlay",
    "ZTUnit",
    "ZTFood",
    "ZTPath",
    "ZTFence",
    "ZTBuilding",
    "ZTAnimal",
    "ZTGuest",
    "ZTScenery",
    "ZTKeeper",
    "ZTMaint",
    "ZTGuide",
    "ZTHelicopter",
    "ZTAmbient",
    "ZTRubble",
    "ZTTankWall",
    "ZTTankFilter",
    "ZTStaff",
]
 
entity_type_names = [
    "BFEntityType",
    "BFUnitType",
    "BFOverlayType",
    "ZTUnitType",
    "ZTFoodType",
    "ZTPathType",
    "ZTFenceType",
    "ZTBuildingType",
    "ZTAnimalType",
    "ZTGuestType",
    "ZTSceneryType",
    "ZTKeeperType",
    "ZTMaintType",
    "ZTGuideType",
    "ZTHelicopterType",
    "ZTAmbientType",
    "ZTRubbleType",
    "ZTTankWallType",
    "ZTTankFilterType",
    "ZTStaffType",
]
 
UNIDENTIFIED_PATTERN = re.compile(r'^(virt_meth|FUN_|thunk_FUN_)')
 
 
def is_identified(name):
    return not UNIDENTIFIED_PATTERN.match(name)
 
 
def normalize_function_name(raw_name):
    # Strip Ghidra duplicate suffixes: save_1, save_2 -> save
    return re.sub(r'_\d+$', '', raw_name)
 
 
def get_function(ctx, addr_str):
    try:
        func = ctx.function_manager.getFunctionContaining(toAddr(addr_str))
    except Exception:
        return None
    if func is None or func.isThunk() or func.isExternal():
        return None
    return func
 
 
def collect_vtable_slots(ctx, class_names):
    """
    Returns { class_name: { offset: (raw_name, addr_str) } }
    """
    by_class = {}
 
    for datatype in currentProgram.getDataTypeManager().getAllDataTypes():
        parts = datatype.getName().split("::")
        if len(parts) < 2:
            continue
        class_name = parts[0]
        table_name = parts[1]
        if class_name not in class_names:
            continue
        if not (table_name.startswith("vftable") or table_name.startswith("vtable")):
            continue
        if type(datatype) is not StructureDB:
            continue
 
        if class_name not in by_class:
            by_class[class_name] = {}
 
        for component in datatype.getDefinedComponents():
            offset = component.getOffset()
            dt = component.getDataType()
            if dt is None or type(dt) is not PointerDB:
                continue
            pointee = dt.getDataType()
            if pointee is None:
                continue
 
            addr_str = pointee.getName().split("_")[-1]
            func = get_function(ctx, addr_str)
            if func is None:
                continue
 
            # Strip any leading 0x so print format "0x%s" does not double it
            clean_addr = addr_str[2:] if addr_str.startswith("0x") or addr_str.startswith("0X") else addr_str
            by_class[class_name][offset] = (func.getName(), clean_addr)
 
    return by_class
 
 
def find_and_print_common_slots(by_class, min_identified=2):
    """
    For each offset where min_identified+ classes share a recognised function name,
    print every class at that offset - flagging the unidentified ones.
    """
    all_offsets = set()
    for slots in by_class.values():
        all_offsets.update(slots.keys())
 
    any_found = False
    num_groups = 0
    total_unidentified = 0
 
    for offset in sorted(all_offsets):
        identified = {}    # norm_name -> [(class_name, raw_name, addr_str)]
        unidentified = []  # [(class_name, raw_name, addr_str)]
 
        for class_name in sorted(by_class.keys()):
            slots = by_class[class_name]
            if offset not in slots:
                continue
            raw_name, addr_str = slots[offset]
            norm = normalize_function_name(raw_name)
            if norm.startswith("nullsub"):
                continue
            if is_identified(raw_name):
                if norm not in identified:
                    identified[norm] = []
                identified[norm].append((class_name, raw_name, addr_str))
            else:
                unidentified.append((class_name, raw_name, addr_str))
 
        if not identified:
            continue
 
        # Skip groups where everything is already identified
        if not unidentified:
            continue
 
        # Separate vf_ names from real names - vf_ functions are generic dummy
        # implementations that only provide useful signal when a real name also
        # exists at the same offset.
        real_identified = {n: e for n, e in identified.items() if not n.startswith("vf_")}
        if not real_identified:
            continue
 
        # Use the real name agreed on by the most classes as the dominant name
        dominant_name = max(real_identified.keys(), key=lambda n: len(real_identified[n]))
        dominant_entries = real_identified[dominant_name]
 
        if len(dominant_entries) < min_identified:
            continue
 
        other_identified = []
        for norm, entries in identified.items():
            if norm != dominant_name:
                other_identified.extend(entries)
        # Sort vf_ entries to print after other real names
        other_identified.sort(key=lambda e: (normalize_function_name(e[1]).startswith("vf_"), e[0]))
 
        any_found = True
        num_groups += 1
        total_unidentified += len(unidentified)
        identified_count = len(dominant_entries) + len(other_identified)
        total = identified_count + len(unidentified)
        print("")
        print("=== %s @ offset 0x%x  (%d identified, %d unidentified, %d total) ===" % (
            dominant_name, offset, identified_count, len(unidentified), total))
 
        for entry in sorted(dominant_entries):
            print("  %-20s  %-30s  0x%s" % entry)
 
        for (class_name, raw_name, addr_str) in other_identified:
            suffix = "  (vf_ stub)" if normalize_function_name(raw_name).startswith("vf_") else "  (different name)"
            print("  %-20s  %-30s  0x%s%s" % (class_name, raw_name, addr_str, suffix))
 
        for (class_name, raw_name, addr_str) in sorted(unidentified):
            print("  %-20s  %-30s  0x%s  <-- unidentified" % (
                class_name, raw_name, addr_str))
 
    if not any_found:
        print("No common identified vtable functions found across %d or more classes." % min_identified)
    return num_groups, total_unidentified
 
 
if __name__ == "__main__":
    ctx = GhidraContext(
        currentProgram,
        currentLocation,
        currentProgram.getFunctionManager(),
        currentProgram.getSymbolTable(),
    )
 
    summaries = []
    for label, class_names in [("Entity", entity_names), ("Entity Types", entity_type_names)]:
        print("\n========== %s ==========" % label)
        by_class = collect_vtable_slots(ctx, class_names)
        print("Collected vtable slots for %d classes." % len(by_class))
        num_groups, total_unidentified = find_and_print_common_slots(by_class, min_identified=2)
        summaries.append((label, num_groups, total_unidentified))
 
    print("\n========== SUMMARY ==========")
    for (label, num_groups, total_unidentified) in summaries:
        print("  %-14s  %d groups,  %d unidentified functions total" % (
            label + ":", num_groups, total_unidentified))
 
