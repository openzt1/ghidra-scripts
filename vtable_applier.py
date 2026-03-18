# vtable_applier.py
# Phases 1-5 of vtable application for CFM/PEF PowerPC Mac binaries.
#
# Phase 1  - Create GhidraClass namespaces for every detected class
# Phase 2  - Re-parent existing functions into their class namespaces
# Phase 3  - Create function stubs at undefined vtable slot addresses
# Phase 3b - Delete empty _namespace_old namespaces
# Phase 4  - Build and stamp vtable structs in the data type manager
# Phase 5  - Create vtable labels in each class namespace
#
# Public entry point:
#   apply_all(ctx, all_vtables) -> class_map
#@runtime Jython

from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.data import (
    CategoryPath, DataTypeConflictHandler, PointerDataType,
    StructureDataType, UnsignedIntegerDataType, IntegerDataType,
)
from ghidra.util.exception import InvalidInputException, DuplicateNameException


# ---------------------------------------------------------------------------
# Phase 1 -- Create GhidraClass namespaces
# ---------------------------------------------------------------------------

def _create_class_namespaces(ctx, all_vtables):
    """
    For every unique class name in all_vtables, ensure a GhidraClass namespace
    exists in the global namespace.

    - If a GhidraClass with that name already exists, reuse it.
    - If a plain Namespace with that name exists, rename it to
      {name}_namespace_old first, then create the GhidraClass.
    - Otherwise create the GhidraClass directly.

    Returns a dict mapping class_name (str) -> GhidraClass.
    """
    global_ns = ctx.program.getGlobalNamespace()
    class_map = {}

    class_names = sorted(set(vt["class_name"] for vt in all_vtables))
    print("Phase 1: Creating {} class namespace(s)...".format(len(class_names)))

    for class_name in class_names:
        existing = ctx.symbol_table.getNamespace(class_name, global_ns)

        if existing is not None:
            if existing.getSymbol().getSymbolType() == SymbolType.CLASS:
                # Already a GhidraClass -- reuse it.
                class_map[class_name] = existing
                print("  REUSED   {}".format(class_name))
                continue

            # A plain Namespace exists -- rename it out of the way.
            old_name = "{}_namespace_old".format(class_name)
            try:
                existing.getSymbol().setName(old_name, SourceType.USER_DEFINED)
                print("  RENAMED  {} -> {}".format(class_name, old_name))
            except (InvalidInputException, DuplicateNameException) as e:
                print("  WARNING  could not rename existing namespace '{}': "
                      "{}".format(class_name, e))

        # Create the GhidraClass.
        try:
            ghidra_class = ctx.symbol_table.createClass(
                global_ns, class_name, SourceType.USER_DEFINED)
            class_map[class_name] = ghidra_class
            print("  CREATED  {}".format(class_name))
        except (InvalidInputException, DuplicateNameException) as e:
            print("  ERROR    could not create class '{}': {}".format(
                class_name, e))

    print("")
    return class_map


# ---------------------------------------------------------------------------
# Phase 2 -- Re-parent existing functions
# ---------------------------------------------------------------------------

# Outcome tags used in logging
_REPARENTED      = "REPARENTED"
_WRONG_PARENT    = "WRONG_PARENT"
_PLAIN_NAMESPACE = "PLAIN_NAMESPACE"
_UNMATCHED_CLASS = "UNMATCHED_CLASS"


def _classify_function(ctx, func, class_map):
    """
    Determine what should happen to func with respect to re-parenting.

    Returns one of:
        (_REPARENTED,      ghidra_class)   -- re-parent into ghidra_class
        (_WRONG_PARENT,    msg)            -- already owned by different class
        (_PLAIN_NAMESPACE, msg)            -- owned by plain namespace for known class
        (_UNMATCHED_CLASS, msg)            -- :: prefix not in class_map
        (None,             None)           -- plain global, skip silently
    """
    full_name = func.getName(True)

    if "::" not in full_name:
        return None, None

    # Strip any _namespace_old suffix introduced when we renamed a plain
    # namespace out of the way during Phase 1, so matching works correctly
    # regardless of the rename.
    class_prefix       = full_name.split("::")[0].replace("_namespace_old", "")
    current_parent     = func.getParentNamespace()
    parent_symbol_type = current_parent.getSymbol().getSymbolType()
    parent_name        = current_parent.getName()
    parent_name_norm   = parent_name.replace("_namespace_old", "")
    is_parent_class    = (parent_symbol_type == SymbolType.CLASS)
    is_parent_global   = current_parent.isGlobal()

    if class_prefix not in class_map:
        return (
            _UNMATCHED_CLASS,
            "function '{}' has class prefix '{}' not in known class map "
            "(current parent: '{}')".format(full_name, class_prefix, parent_name)
        )

    target_class = class_map[class_prefix]

    if is_parent_class:
        if parent_name == class_prefix:
            # Already correctly parented -- nothing to do, skip silently.
            return None, None
        # Owned by a different GhidraClass (inherited / wrong assignment).
        return (
            _WRONG_PARENT,
            "function '{}' belongs to class prefix '{}' but is already owned "
            "by GhidraClass '{}' -- possible inherited method, skipping".format(
                full_name, class_prefix, parent_name)
        )

    if not is_parent_global:
        if parent_name_norm == class_prefix:
            # Parent is one of our renamed namespaces -- re-parent silently.
            return _REPARENTED, target_class
        # Owned by some other plain namespace we did not create.
        return (
            _PLAIN_NAMESPACE,
            "function '{}' belongs to class prefix '{}' but current parent "
            "'{}' is a plain Namespace, not a GhidraClass".format(
                full_name, class_prefix, parent_name)
        )

    # Parent is global namespace -- safe to re-parent.
    return _REPARENTED, target_class


def _reparent_existing_functions(ctx, class_map):
    """
    Iterate all functions in the program and re-parent any whose name or
    current namespace indicates they belong to a known class.

    Logs outcomes for every function that has a '::' prefix, grouped by
    outcome type.  Functions without '::' are silently skipped.
    """
    counts = {
        _REPARENTED:      0,
        _WRONG_PARENT:    0,
        _PLAIN_NAMESPACE: 0,
        _UNMATCHED_CLASS: 0,
    }
    log = {
        _WRONG_PARENT:    [],
        _PLAIN_NAMESPACE: [],
        _UNMATCHED_CLASS: [],
    }

    print("Phase 2: Re-parenting functions...")

    funcs = ctx.function_manager.getFunctions(True)
    while funcs.hasNext():
        func = funcs.next()
        outcome, payload = _classify_function(ctx, func, class_map)

        if outcome is None:
            continue

        if outcome == _REPARENTED:
            try:
                # Strip the class prefix from the function's simple name
                # before re-parenting.  Without this, moving
                # "ZTGoalLeave::checkDone" into the ZTGoalLeave namespace
                # produces "ZTGoalLeave::ZTGoalLeave::checkDone".
                simple_name = func.getName()
                prefix = payload.getName() + "::"
                if simple_name.startswith(prefix):
                    simple_name = simple_name[len(prefix):]
                    func.setName(simple_name, SourceType.USER_DEFINED)
                func.setParentNamespace(payload)
                counts[_REPARENTED] += 1
            except (InvalidInputException, DuplicateNameException) as e:
                print("  WARNING  could not re-parent '{}': {}".format(
                    func.getName(True), e))
        else:
            counts[outcome] += 1
            log[outcome].append(payload)

    # Print summary counts.
    print("  Re-parented:    {}".format(counts[_REPARENTED]))
    print("  Wrong parent:   {}".format(counts[_WRONG_PARENT]))
    print("  Plain namespace:{}".format(counts[_PLAIN_NAMESPACE]))
    print("  Unmatched class:{}".format(counts[_UNMATCHED_CLASS]))
    print("")

    # Print detail lines for every non-silent outcome.
    if log[_WRONG_PARENT]:
        print("  -- WRONG_PARENT (inherited / conflicting ownership) --")
        for msg in log[_WRONG_PARENT]:
            print("    {}".format(msg))
        print("")

    if log[_PLAIN_NAMESPACE]:
        print("  -- PLAIN_NAMESPACE (Ghidra analysis inconsistency) --")
        for msg in log[_PLAIN_NAMESPACE]:
            print("    {}".format(msg))
        print("")

    if log[_UNMATCHED_CLASS]:
        print("  -- UNMATCHED_CLASS (no vtable found for this class) --")
        for msg in log[_UNMATCHED_CLASS]:
            print("    {}".format(msg))
        print("")


# ---------------------------------------------------------------------------
# Phase 3 -- Create function stubs at undefined slot addresses
# ---------------------------------------------------------------------------

def _create_missing_functions(ctx, all_vtables):
    """
    For every vtable slot that resolved to a code address but has no function
    defined there, ask Ghidra to create and analyse a function at that address.

    These stubs are intentionally left in the global namespace -- they have
    auto-generated FUN_ names and no :: prefix, so Phase 2 will not touch
    them.  Once manually named (e.g. ClassName::method), a subsequent run of
    Phase 2 will re-parent them automatically.
    """
    # Collect the unique set of undefined code addresses across all vtables.
    pending = set()
    for vt in all_vtables:
        for addr_str in vt["undefined_addrs"]:
            pending.add(addr_str)

    print("Phase 3: Creating {} missing function stub(s)...".format(
        len(pending)))

    created = 0
    skipped = 0
    failed  = 0

    for addr_str in sorted(pending):
        code_addr = ctx.flat_api.toAddr(addr_str)

        # Double-check: another vtable's pass may have already created it.
        if ctx.function_manager.getFunctionAt(code_addr) is not None:
            skipped += 1
            continue

        try:
            func = ctx.flat_api.createFunction(code_addr, None)
            if func is not None:
                created += 1
            else:
                print("  WARNING  createFunction returned None @ {}".format(
                    addr_str))
                failed += 1
        except Exception as e:
            print("  WARNING  could not create function @ {}: {}".format(
                addr_str, e))
            failed += 1

    print("  Created: {}  Skipped (already existed): {}  Failed: {}".format(
        created, skipped, failed))
    print("")


# ---------------------------------------------------------------------------
# Phase 3b -- Delete empty _namespace_old namespaces
# ---------------------------------------------------------------------------

def _delete_empty_old_namespaces(ctx):
    """
    Delete any namespace whose name ends with _namespace_old and that has no
    remaining child symbols.  These were created by Phase 1 when renaming
    plain namespaces out of the way; Phase 2 should have re-parented all
    their functions into the new GhidraClass.  Any that are still non-empty
    are left in place and logged as a warning.
    """
    print("Phase 3b: Deleting empty _namespace_old namespace(s)...")

    deleted  = 0
    nonempty = 0
    global_ns = ctx.program.getGlobalNamespace()

    # Collect all matching namespace symbols up front -- deleting while
    # iterating the symbol table is not safe.
    old_ns_symbols = [
        sym for sym in ctx.symbol_table.getChildren(global_ns.getSymbol())
        if sym.getName().endswith("_namespace_old")
    ]

    for sym in old_ns_symbols:
        children = list(ctx.symbol_table.getChildren(sym))
        if children:
            nonempty += 1
            print("  WARNING  '{}' still has {} child symbol(s) -- not "
                  "deleted".format(sym.getName(), len(children)))
            for child in children:
                print("           - {}".format(child.getName(True)))
        else:
            try:
                sym.delete()
                deleted += 1
                print("  DELETED  {}".format(sym.getName()))
            except Exception as e:
                print("  ERROR    could not delete '{}': {}".format(
                    sym.getName(), e))

    print("  Deleted: {}  Non-empty (skipped): {}".format(deleted, nonempty))
    print("")


# ---------------------------------------------------------------------------
# Phase 4 -- Build and stamp vtable structs
# ---------------------------------------------------------------------------

def _slot_field_name(ctx, slot_addr, slot_index):
    """
    Derive a struct field name for a single vtable slot.

    - Named function  -> simple function name (no namespace prefix)
    - FUN_/LAB_ or no function -> "slot_N"
    """
    from vtable_finder import resolve_slot_to_code
    code_addr = resolve_slot_to_code(ctx, slot_addr)
    if code_addr is not None:
        func = ctx.function_manager.getFunctionAt(code_addr)
        if func is None:
            func = ctx.function_manager.getFunctionContaining(code_addr)
        if func is not None:
            name = func.getName()
            if not name.startswith("FUN_") and not name.startswith("LAB_"):
                return name
    return "slot_{}".format(slot_index)


def _build_vtable_struct(ctx, vt, struct_name):
    """
    Build a StructureDataType for a single vtable (primary or secondary).

    Layout:
        +0x00  rtti_ptr    pointer   (points at the RTTI struct)
        +0x04  base_offset int       (0 for primary; signed this-offset for secondary)
        +0x08  <slot 0>    pointer   (or uint for gap words)
        ...

    Returns the registered StructureDataType.
    """
    dtm        = ctx.data_type_manager
    ptr_type   = PointerDataType(dtm)
    int_type   = IntegerDataType(dtm)
    uint_type  = UnsignedIntegerDataType(dtm)

    category   = CategoryPath("/vtables")
    struct     = StructureDataType(category, struct_name, 0, dtm)

    # Header fields
    struct.add(ptr_type, 4, "rtti_ptr",    "Pointer to RTTI struct")
    struct.add(int_type, 4, "base_offset",
               "0 for primary vtable; signed this-ptr adjustment for secondary")

    # Slot fields
    from vtable_finder import _read_word, _is_gap_word
    addr      = vt["slots_start"]
    gap_index = 0

    for i in range(vt["slot_count"]):
        word = _read_word(ctx, addr)

        if _is_gap_word(word):
            struct.add(uint_type, 4, "gap_{}".format(gap_index), "gap / null slot")
            gap_index += 1
        else:
            field_name = _slot_field_name(ctx, addr, i)
            struct.add(ptr_type, 4, field_name, "")

        addr = addr.add(4)

    # Register, replacing any previous version of this struct.
    registered = dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
    return registered


def _stamp_vtable_struct(ctx, vt, struct_type):
    """
    Clear any existing data covering the vtable's byte range in the listing
    and stamp the struct data type at header_addr.
    """
    start_addr = vt["header_addr"]
    length     = struct_type.getLength()
    end_addr   = start_addr.add(length - 1)

    ctx.listing.clearCodeUnits(start_addr, end_addr, False)
    try:
        ctx.listing.createData(start_addr, struct_type)
    except Exception as e:
        print("  WARNING  could not stamp struct '{}' @ {}: {}".format(
            struct_type.getName(), start_addr, e))


def _build_vtable_structs(ctx, all_vtables):
    """
    For each vtable (primary and secondary), build a StructureDataType,
    register it under /vtables/ClassName, and stamp it at header_addr.

    Struct naming:
        Primary:   ClassName_vtable
        Secondary: ClassName_vtable_secondary_N  (1-indexed per class)
    """
    print("Phase 4: Building vtable struct(s)...")

    # Track secondary index per class name.
    secondary_counts = {}
    created = 0

    for vt in all_vtables:
        class_name = vt["class_name"]

        if vt["is_secondary"]:
            secondary_counts[class_name] = secondary_counts.get(class_name, 0) + 1
            struct_name = "{}_vtable_secondary_{}".format(
                class_name, secondary_counts[class_name])
        else:
            struct_name = "{}_vtable".format(class_name)

        try:
            struct_type = _build_vtable_struct(ctx, vt, struct_name)
            _stamp_vtable_struct(ctx, vt, struct_type)
            created += 1
            print("  BUILT    {} @ {} ({} bytes)".format(
                struct_name, vt["header_addr"], struct_type.getLength()))
        except Exception as e:
            print("  ERROR    could not build '{}': {}".format(struct_name, e))

    print("  Built: {}".format(created))
    print("")


# ---------------------------------------------------------------------------
# Phase 5 -- Create vtable labels in each class namespace
# ---------------------------------------------------------------------------

def _create_vtable_labels(ctx, all_vtables, class_map):
    """
    Create a named label at each vtable's header_addr inside the owning
    GhidraClass namespace, so vtables appear in the symbol tree as
    ClassName::vtable and ClassName::vtable_secondary_N.

    Any existing label with the same name at the same address is removed
    first to avoid duplicates.  The new label is set as primary.
    """
    print("Phase 5: Creating vtable label(s)...")

    secondary_counts = {}
    created = 0

    for vt in all_vtables:
        class_name = vt["class_name"]
        ghidra_class = class_map.get(class_name)
        if ghidra_class is None:
            print("  WARNING  no GhidraClass for '{}' -- skipping "
                  "label".format(class_name))
            continue

        if vt["is_secondary"]:
            secondary_counts[class_name] = secondary_counts.get(class_name, 0) + 1
            label_name = "vtable_secondary_{}".format(
                secondary_counts[class_name])
        else:
            label_name = "vtable"

        header_addr = vt["header_addr"]

        # Remove any existing label with this name at this address.
        for sym in ctx.symbol_table.getSymbols(header_addr):
            if sym.getName() == label_name and sym.getParentNamespace() == ghidra_class:
                sym.delete()

        try:
            sym = ctx.symbol_table.createLabel(
                header_addr, label_name, ghidra_class, SourceType.USER_DEFINED)
            sym.setPrimary()
            created += 1
            print("  LABELLED {}::{} @ {}".format(
                class_name, label_name, header_addr))
        except Exception as e:
            print("  ERROR    could not create label '{}::{}' @ {}: {}".format(
                class_name, label_name, header_addr, e))

    print("  Labelled: {}".format(created))
    print("")


# ---------------------------------------------------------------------------
# Phase 6 -- Create class instance structs
# ---------------------------------------------------------------------------

def _create_class_structs(ctx, all_vtables, class_map):
    """
    For every class that has a primary vtable, create a StructureDataType
    named after the class under the /classes category path.

    The struct starts with a single field:
        +0x00  vtable   ClassName_vtable *   (pointer to the vtable struct)

    All remaining fields are left undefined -- they will be filled in
    manually as analysis progresses.  Re-running the script replaces the
    struct via REPLACE_HANDLER, so the vtable pointer field is always kept
    up to date even if the struct already exists.
    """
    print("Phase 6: Creating class instance struct(s)...")

    dtm      = ctx.data_type_manager
    category = CategoryPath("/classes")
    created  = 0

    # Build a lookup of primary vtable struct by class name so we can type
    # the vtable pointer field correctly.
    vtable_struct_map = {}
    for vt in all_vtables:
        if not vt["is_secondary"]:
            vtable_struct_name = "{}_vtable".format(vt["class_name"])
            existing_dt = dtm.getDataType(CategoryPath("/vtables"), vtable_struct_name)
            if existing_dt is not None:
                vtable_struct_map[vt["class_name"]] = existing_dt

    # Only create instance structs for classes we have a GhidraClass for.
    for class_name in sorted(class_map.keys()):
        struct = StructureDataType(category, class_name, 0, dtm)

        # Type the vtable pointer field if we have the vtable struct available,
        # otherwise fall back to a plain void pointer.
        vtable_dt = vtable_struct_map.get(class_name)
        if vtable_dt is not None:
            vtable_ptr = PointerDataType(vtable_dt, dtm)
            comment    = "Pointer to {} vtable".format(class_name)
        else:
            vtable_ptr = PointerDataType(dtm)
            comment    = "Pointer to vtable (struct not found)"

        struct.add(vtable_ptr, 4, "vtable", comment)

        try:
            dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)
            created += 1
            print("  CREATED  /classes/{}".format(class_name))
        except Exception as e:
            print("  ERROR    could not create struct for '{}': {}".format(
                class_name, e))

    print("  Created: {}".format(created))
    print("")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def apply_all(ctx, all_vtables):
    """
    Run all phases against the provided vtable list.

    Phase 1  -- Create GhidraClass namespaces
    Phase 2  -- Re-parent existing functions by name / namespace
    Phase 3  -- Create function stubs at undefined slot addresses
    Phase 3b -- Delete empty _namespace_old namespaces
    Phase 4  -- Build and stamp vtable structs
    Phase 5  -- Create vtable labels in each class namespace
    Phase 6  -- Create class instance structs

    All writes must be wrapped in a transaction by the caller.

    Returns the class_map dict (class_name -> GhidraClass) for use in
    subsequent phases.
    """
    class_map = _create_class_namespaces(ctx, all_vtables)
    _reparent_existing_functions(ctx, class_map)
    _create_missing_functions(ctx, all_vtables)
    _delete_empty_old_namespaces(ctx)
    _build_vtable_structs(ctx, all_vtables)
    _create_vtable_labels(ctx, all_vtables, class_map)
    _create_class_structs(ctx, all_vtables, class_map)
    return class_map
