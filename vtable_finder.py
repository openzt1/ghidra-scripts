# vtable_finder.py
# Vtable detection module for CFM/PEF PowerPC Mac binaries.
# Import this module, then call find_all_vtables(ctx) to run the full scan.
# All functions accept a GhidraContext as their first argument.


from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.util import DefinedStringIterator


# ---------------------------------------------------------------------------
# Class name collection
# ---------------------------------------------------------------------------

# Add any class names you want to force-include here
MANUAL_CLASS_NAMES = set([
    "Ambients",
    "AmbientsGroup",
    "BF3DSorter",
    "BFAIMgr",
    "BFAnimCache",
    "BFApp",
    "BFBehaviorSet",
    "BFBSCall",
    "BFCogGoal",
    "BFConfigFile",
    "BFEntity",
    "BFEntityType",
    "BFEvent",
    "BFEventInfo",
    "BFEventListenerInterface",
    "BFEventMgr",
    "BFFont",
    "BFFontCache",
    "BFFontDescription",
    "BFFunctionCall",
    "BFGameApp",
    "BFGameMgr",
    "BFGoal",
    "BFGoalFactory",
    "BFIniFile",
    "bfinternat",
    "BFLog",
    "BFMap",
    "BFMgr",
    "BFObject",
    "BFOldGoal",
    "BFPathFinder",
    "BFRegistry",
    "BFResMemTrack",
    "BFResource",
    "BFResourceMgr",
    "BFResourcePtr",
    "BFResourceZip",
    "BFScenarioMgr",
    "BFScriptMgr",
    "BFSoundMgr",
    "BFSubGoal",
    "BFTerrainMgr",
    "BFText",
    "BFTile",
    "BFUIMgr",
    "BFUnit",
    "BFUnitType",
    "BFVersionInfo",
    "BFWindow",
    "BFWindowClass",
    "BFWorldMgr",
    "FullScreen",
    "GDI32.DLL",
    "GXCanvas",
    "GXGraphicsMgr",
    "GXImage",
    "GXLLE",
    "GXLLEAnimSet",
    "GXMixer",
    "GXMixerLink",
    "GXPaletteMap",
    "GXVideoManager",
    "SNDSound",
    "Sorter",
    "SoundGroup",
    "std",
    "UBEntry",
    "UICallbackMgr",
    "UIControl",
    "UIElement",
    "UIElementIniter<11UIScrollBar>\"",
    "UIElementIniter<6UIText>\"",
    "UIElementIniter<6UIView>\"",
    "UIElementIniter<9ZTMapView>\"",
    "UILayout",
    "UIListBox",
    "UIListBoxEntry",
    "UIListBoxItem",
    "UIMessageQueue",
    "UIRadioSet",
    "UIScrollBar",
    "UIScrollingRegion",
    "UIStatusImage",
    "UIText",
    "UIView",
    "ZooStatus",
    "ZTAdvTerrainMgr",
    "ZTAIMgr",
    "STAmbient",
    "ZTAmbientType",
    "ZTAnimal",
    "ZTAnimalType",
    "ZTApp",
    "ZTAssignHabitatMode",
    "ZTAwardMgr",
    "ZTBuilding",
    "ZTBuildingType",
    "ZTBulldozerMode",
    "ZTCheat",
    "ZTEcon",
    "ZTFence",
    "ZTFenceType",
    "ZTFood",
    "ZTFoodType",
    "ZTGameMgr",
    "ZTGoalAvoid",
    "ZTGoalBagDoo",
    "ZTGoalChase",
    "ZTGoalChaseAnimal",
    "ZTGoalEmptyTrash",
    "ZTGoalFactory",
    "ZTGoalPreattack",
    "ZTGoalTankEnter",
    "ZTGoalZoo",
    "ZTGuest",
    "ZTGuestType",
    "ZTHabitat",
    "ZTHabitatMgr",
    "ZTItem",
    "ZTMaint",
    "ZTMaintType",
    "ZTMaintTaskPool",
    "ZTMapView",
    "ZTMarketingMgr",
    "ZTMegatileMgr",
    "ZTMVTempEntityList",
    "ZTObservableArea",
    "ZTPathType",
    "ZTPath",
    "ZTResearchBranch",
    "ZTResearchMgr",
    "ZTRubble",
    "ZTRubbleType",
    "ZTScenarioGoal",
    "ZTScenarioMgr",
    "ZTScenarioTimer",
    "ZTScenery",
    "ZTSceneryType",
    "ZTShow",
    "ZTShowInfo",
    "ZTShowMgr",
    "ZTSoundscape",
    "ZTStaffType",
    "ZTStaff",
    "ZTGuide",
    "ZTKeeper",
    "ZTHelicopter",
    "ZTGuideType",
    "ZTKeeperType",
    "ZTHelicopterType",
    "ZTTankExhibit",
    "ZTTankFilter",
    "ZTTankFilterType",
    "ZTTankHeightMode",
    "ZTTankWall",
    "ZTTankWallType",
    "ZTTerraformMode",
    "ZTThoughtMgr",
    "ZTUI",
    "ZTUndoBuffer",
    "ZTUnit",
    "ZTUnitType",
    "ZTViewingArea",
    "ZTVisibilityTesting",
    "ZTWorldMgr",
    "ZTUndoBuffer",
"IDirect3DMaterial_Mac",
"IDirect3DViewport_Mac",
"IDirectDraw_Mac",
"IDirect3DVertexBuffer_Mac",
"IDirect3DLight_Mac",
"IDirect3DTexture_Mac",
"IDirect3D_Mac",
"IDirectDrawPalette_Mac",
"IDirectDrawGammaControl_Mac",
"IDirectDrawClipper_Mac",
"IDirectSoundBuffer_Mac",
"IDirectSound_Mac",
"IDirectSound3DListener_Mac",
"IDirectSound3DBuffer_Mac",
"HFONT_Mac",
"HPEN_Mac",
"HBRUSH_Mac",
"IDirectDrawSurface_Mac",
])

# Maximum number of consecutive null words to skip within a vtable
MAX_GAP_WORDS = 1


def get_all_class_names(ctx):
    """
    Collect class names by iterating all functions and splitting on ::.
    Ignores any name containing _, < or >.
    Unions with MANUAL_CLASS_NAMES.
    Returns a sorted list of class name strings.
    """
    class_names = set()

    funcs = ctx.function_manager.getFunctions(True)
    while funcs.hasNext():
        func = funcs.next()
        full_name = func.getName(True)

        if "::" not in full_name:
            continue
        if "_" in full_name or "<" in full_name or ">" in full_name:
            continue

        class_name = full_name.split("::")[0]

        if "_" in class_name or "<" in class_name or ">" in class_name:
            continue
        if len(class_name) < 2:
            continue

        class_names.add(class_name)

    class_names.update(MANUAL_CLASS_NAMES)
    return sorted(class_names)


# ---------------------------------------------------------------------------
# String map
# ---------------------------------------------------------------------------

def get_defined_strings(ctx):
    """
    Iterate all defined strings once and return a dict mapping
    string value -> list of addresses.
    """
    string_map = {}

    data_iter = DefinedStringIterator.forProgram(ctx.program)
    while data_iter.hasNext():
        data = data_iter.next()
        val = data.getValue()
        if val is None:
            continue
        try:
            s = str(val)
        except UnicodeEncodeError:
            continue
        if s not in string_map:
            string_map[s] = []
        string_map[s].append(data.getAddress())

    return string_map


# ---------------------------------------------------------------------------
# Memory helpers
# ---------------------------------------------------------------------------

def _read_ptr(ctx, addr):
    try:
        val = ctx.memory.getInt(addr) & 0xFFFFFFFF
        if val == 0:
            return None
        return ctx.flat_api.toAddr(val)
    except MemoryAccessException:
        return None


def _read_word(ctx, addr):
    try:
        return ctx.memory.getInt(addr) & 0xFFFFFFFF
    except MemoryAccessException:
        return None


def _is_in_blocks(addr, blocks):
    for block in blocks:
        if block.contains(addr):
            return True
    return False


def _is_gap_word(word):
    """
    Returns True if word is a null padding word that may appear within
    a vtable (0x00000000 only).
    """
    if word is None:
        return False
    return word == 0x00000000


def _is_this_offset_word(word):
    """
    Returns True if word looks like a this-pointer adjustment offset,
    i.e. a small negative integer (>= 0xFFF00000) marking the start of a
    secondary vtable block in a multiple-inheritance layout.
    e.g. 0xFFFFFF30 = -208, 0xFFFFFFF0 = -16.
    """
    if word is None:
        return False
    return (word & 0xFFF00000) == 0xFFF00000


# ---------------------------------------------------------------------------
# Slot validation
# ---------------------------------------------------------------------------

def resolve_slot_to_code(ctx, addr):
    """
    Resolve a 4-byte vtable slot to a code address.
    Handles direct pointers and CFM/PEF double-indirection
    (slot -> data descriptor -> code).
    Returns the resolved code address, or None if it does not land in any
    code block.  Does NOT check whether a function exists there.
    """
    target = _read_ptr(ctx, addr)
    if target is None:
        return None
    if _is_in_blocks(target, ctx.code_blocks):
        return target
    if _is_in_blocks(target, ctx.data_blocks):
        deref = _read_ptr(ctx, target)
        if deref is not None and _is_in_blocks(deref, ctx.code_blocks):
            return deref
    return None


def is_valid_slot(ctx, addr):
    """
    Returns the resolved code address if the 4-byte value at addr is a valid
    vtable slot, or None if not.

    A slot is valid if it resolves to a code address (direct or CFM indirect)
    AND that address has a function entry point, falls inside a known function
    body, or at minimum has a decoded instruction.
    """
    code_addr = resolve_slot_to_code(ctx, addr)
    if code_addr is None:
        return None

    if ctx.function_manager.getFunctionAt(code_addr) is not None:
        return code_addr

    # Slot lands inside a known function body (e.g. CFM thunk offset).
    if ctx.function_manager.getFunctionContaining(code_addr) is not None:
        return code_addr

    # Last resort: at least a decoded instruction must exist.
    if ctx.listing.getInstructionAt(code_addr) is not None:
        return code_addr

    return None


# ---------------------------------------------------------------------------
# Slot counting and analysis
# ---------------------------------------------------------------------------

def count_slots(ctx, slots_start):
    """
    Count valid vtable slots starting at slots_start, allowing up to
    MAX_GAP_WORDS consecutive null words between valid slots.
    Stops on a this-pointer adjustment word (secondary vtable boundary).
    Returns the slot count with trailing gaps trimmed.
    """
    count = 0
    addr = slots_start
    gap = 0

    while True:
        word = _read_word(ctx, addr)
        if word is None:
            break

        if _is_this_offset_word(word):
            break

        if _is_gap_word(word):
            gap += 1
            if gap > MAX_GAP_WORDS:
                break
            count += 1
            addr = addr.add(4)
            continue

        if is_valid_slot(ctx, addr) is None:
            break

        gap = 0
        count += 1
        addr = addr.add(4)

    # Trim trailing gap slots
    if count > 0:
        trim_addr = slots_start.add((count - 1) * 4)
        while count > 0:
            word = _read_word(ctx, trim_addr)
            if _is_gap_word(word):
                count -= 1
                trim_addr = trim_addr.subtract(4)
            else:
                break

    return count


def get_undefined_slots(ctx, slots_start, slot_count):
    """
    Return a set of address strings for slots that resolve to functions that
    are unnamed (FUN_/LAB_) or have no function defined at all.
    Gap words are skipped.
    """
    undefined_addrs = set()
    addr = slots_start

    for i in range(slot_count):
        word = _read_word(ctx, addr)

        if _is_gap_word(word):
            addr = addr.add(4)
            continue

        code_addr = is_valid_slot(ctx, addr)
        if code_addr is None:
            undefined_addrs.add(str(addr))
        else:
            func = ctx.function_manager.getFunctionAt(code_addr)
            if func is None:
                undefined_addrs.add(str(code_addr))
            else:
                name = func.getName()
                if name.startswith("FUN_") or name.startswith("LAB_"):
                    undefined_addrs.add(str(code_addr))

        addr = addr.add(4)

    return undefined_addrs


# ---------------------------------------------------------------------------
# Superclass list parsing
# ---------------------------------------------------------------------------

def _parse_superclass_list(ctx, superclass_list_addr):
    """
    Parse the superclass list structure.
    Format: repeated [ptr to RTTI struct][null word] entries, terminated by
    a null word.
    Returns list of superclass name strings.
    """
    superclasses = []
    addr = superclass_list_addr

    while True:
        word = _read_word(ctx, addr)
        if word is None or word == 0x00000000:
            break

        entry_ptr = ctx.flat_api.toAddr(word)
        if not _is_in_blocks(entry_ptr, ctx.data_blocks):
            break

        string_ptr = _read_ptr(ctx, entry_ptr)
        if string_ptr is None:
            break

        try:
            name = ""
            str_addr = string_ptr
            for _ in range(64):
                b = ctx.memory.getByte(str_addr) & 0xFF
                if b == 0:
                    break
                if 32 <= b <= 126:
                    name += chr(b)
                else:
                    name = None
                    break
                str_addr = str_addr.add(1)
            if name and len(name) >= 2:
                superclasses.append(name)
        except MemoryAccessException:
            pass

        addr = addr.add(8)

    return superclasses


# ---------------------------------------------------------------------------
# Secondary vtable detection
# ---------------------------------------------------------------------------

def _find_secondary_vtables(ctx, class_name, primary_header, primary_slot_count):
    """
    Scan forward from the end of a primary vtable for secondary vtable blocks
    arising from multiple inheritance.

    Secondary block layout (CFM/PEF Mac ABI):
        [RTTI ptr]         word[0]: data pointer (same or related RTTI struct)
        [this-offset]      word[1]: small negative value e.g. 0xFFFFFF30
        [slot 0 ...]       word[2]+: vtable slots

    Returns a list of vtable info dicts with is_secondary=True.
    """
    secondaries = []
    addr = primary_header.add(8 + primary_slot_count * 4)

    for _ in range(32):  # safety cap -- no class has 32 base interfaces
        word0 = _read_word(ctx, addr)
        if word0 is None:
            break

        rtti_candidate = ctx.flat_api.toAddr(word0)
        if not _is_in_blocks(rtti_candidate, ctx.data_blocks):
            break

        word1 = _read_word(ctx, addr.add(4))
        if word1 is None:
            break

        if not _is_this_offset_word(word1):
            break

        slots_start = addr.add(8)
        slot_count = count_slots(ctx, slots_start)
        if slot_count < 1:
            break

        undefined_addrs = get_undefined_slots(ctx, slots_start, slot_count)
        signed_offset = word1 if word1 < 0x80000000 else word1 - 0x100000000

        secondaries.append({
            "class_name":      class_name,
            "string_addr":     None,
            "rtti_addr":       rtti_candidate,
            "header_addr":     addr,
            "slots_start":     slots_start,
            "slot_count":      slot_count,
            "undefined_slots": len(undefined_addrs),
            "undefined_addrs": undefined_addrs,
            "superclasses":    [],
            "is_secondary":    True,
            "this_offset":     signed_offset,
        })

        addr = slots_start.add(slot_count * 4)

    return secondaries


# ---------------------------------------------------------------------------
# Primary vtable detection
# ---------------------------------------------------------------------------

def find_vtable_for_class(ctx, class_name, string_addrs):
    """
    Given the string addresses for a class name, walk the RTTI indirection
    chain to find all vtable headers and any secondary vtable blocks.
    Returns (list of vtable info dicts, list of failure reason strings).
    """
    vtable_candidates = []
    failures = []

    for str_addr in string_addrs:
        refs_to_string = list(ctx.flat_api.getReferencesTo(str_addr))
        if not refs_to_string:
            failures.append("str @ {}: no refs to string".format(str_addr))
            continue

        for ref1 in refs_to_string:
            rtti_addr = ref1.getFromAddress()
            if not _is_in_blocks(rtti_addr, ctx.data_blocks):
                failures.append(
                    "str @ {}: ref from {} not in data block".format(
                        str_addr, rtti_addr))
                continue

            # Confirm RTTI struct: first word must equal the string address.
            first_word = _read_ptr(ctx, rtti_addr)
            if first_word is None or first_word != str_addr:
                failures.append(
                    "str @ {}: data ref @ {} first word 0x{:08x} != string "
                    "addr (not an RTTI struct)".format(
                        str_addr, rtti_addr,
                        _read_word(ctx, rtti_addr) or 0))
                continue

            # Parse optional superclass list from second word of RTTI struct.
            superclasses = []
            second_word_raw = _read_word(ctx, rtti_addr.add(4))
            if second_word_raw is not None and second_word_raw != 0:
                second_word = ctx.flat_api.toAddr(second_word_raw)
                if _is_in_blocks(second_word, ctx.data_blocks):
                    superclasses = _parse_superclass_list(ctx, second_word)

            refs_to_rtti = list(ctx.flat_api.getReferencesTo(rtti_addr))
            if not refs_to_rtti:
                failures.append(
                    "rtti @ {}: no refs to RTTI struct".format(rtti_addr))
                continue

            for ref2 in refs_to_rtti:
                candidate_header = ref2.getFromAddress()
                if not _is_in_blocks(candidate_header, ctx.data_blocks):
                    failures.append(
                        "rtti @ {}: ref from {} not in data block".format(
                            rtti_addr, candidate_header))
                    continue

                # header+4 must be zero (primary vtable) or a this-offset
                # (which would make this a secondary header, not primary).
                null_word = _read_word(ctx, candidate_header.add(4))
                if null_word is None:
                    failures.append(
                        "header @ {}: cannot read word at header+4".format(
                            candidate_header))
                    continue
                if null_word != 0x00000000:
                    failures.append(
                        "header @ {}: header+4 is 0x{:08x}, expected "
                        "0x00000000".format(candidate_header, null_word))
                    continue

                # First slot (header+8) must resolve to a function or
                # instruction.
                first_slot_code = is_valid_slot(ctx, candidate_header.add(8))
                if first_slot_code is None:
                    raw = _read_word(ctx, candidate_header.add(8))
                    failures.append(
                        "header @ {}: first slot (0x{:08x}) does not resolve "
                        "to a function or instruction".format(
                            candidate_header, raw or 0))
                    continue

                slots_start = candidate_header.add(8)
                slot_count = count_slots(ctx, slots_start)
                if slot_count < 1:
                    failures.append(
                        "header @ {}: no valid slots found".format(
                            candidate_header))
                    continue

                undefined_addrs = get_undefined_slots(
                    ctx, slots_start, slot_count)

                vtable_candidates.append({
                    "class_name":      class_name,
                    "string_addr":     str_addr,
                    "rtti_addr":       rtti_addr,
                    "header_addr":     candidate_header,
                    "slots_start":     slots_start,
                    "slot_count":      slot_count,
                    "undefined_slots": len(undefined_addrs),
                    "undefined_addrs": undefined_addrs,
                    "superclasses":    superclasses,
                    "is_secondary":    False,
                    "this_offset":     0,
                })

                secondaries = _find_secondary_vtables(
                    ctx, class_name, candidate_header, slot_count)
                vtable_candidates.extend(secondaries)

    # Keep only the candidate with the most slots per RTTI struct (primary),
    # or per slots_start address (secondary).
    deduped = {}
    for vt in vtable_candidates:
        key = ("secondary:{}".format(vt["slots_start"])
               if vt["is_secondary"]
               else "primary:{}".format(vt["rtti_addr"]))
        if key not in deduped or vt["slot_count"] > deduped[key]["slot_count"]:
            deduped[key] = vt

    return list(deduped.values()), failures


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------

def find_all_vtables(ctx):
    """
    Run the full vtable scan for all known class names.

    Returns a tuple of:
        all_vtables  -- list of vtable info dicts (primary and secondary)
        no_string    -- list of class names with no string found in the binary
        no_vtable    -- list of (class_name, [failure strings]) for classes
                        whose string was found but no vtable could be detected
    """
    print("Step 1: Collecting class names...")
    class_names = get_all_class_names(ctx)
    print("Found {} class name(s)".format(len(class_names)))
    print("")

    print("Step 2: Building defined string map...")
    string_map = get_defined_strings(ctx)
    print("Found {} defined string(s)".format(len(string_map)))
    print("")

    print("Step 3: Scanning for vtables...")
    print("")

    all_vtables = []
    no_string   = []
    no_vtable   = []

    for class_name in class_names:
        string_addrs = string_map.get(class_name, [])
        if not string_addrs:
            no_string.append(class_name)
            continue

        vtables, failures = find_vtable_for_class(ctx, class_name, string_addrs)

        if not vtables:
            no_vtable.append((class_name, failures))
            continue

        for vt in vtables:
            all_vtables.append(vt)

            if vt["is_secondary"]:
                tag      = "SECONDARY"
                extra    = " this_offset={}".format(vt["this_offset"])
                heritage = ""
            else:
                tag      = "FOUND    "
                extra    = ""
                heritage = (" extends: {}".format(", ".join(vt["superclasses"]))
                            if vt["superclasses"] else "")

            print("  {}  {} @ {} ({} slots, {} undefined){}{}".format(
                tag,
                vt["class_name"],
                vt["header_addr"],
                vt["slot_count"],
                vt["undefined_slots"],
                heritage,
                extra))

    return all_vtables, no_string, no_vtable
