# Metrowerks Debug-Namespace Organiser for Ghidra
# Jython (Python 2) compatible
#
# 1. Finds every function in the '.debug' namespace.
# 2. Re-demangles its name via mw_demangle.
# 3. Parses the demangled signature to extract class/namespace, bare name,
#    and parameter list.
# 4. Moves the function into the correct class or namespace.
# 5. Renames it to just the bare function name.
# 6. Prepends a plate comment with the full demangled signature.
#
# Requires mw_demangle.py to be on the Ghidra script path.
#
# @author   mw_organise
# @category Analysis
# @menupath Analysis.Metrowerks Organise Debug Namespace
# @toolbar
# @runtime Jython

import re

import mw_demangle

from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import DuplicateNameException


# ---------------------------------------------------------------------------
#  Signature parser
# ---------------------------------------------------------------------------

# Matches:   Some::Nested::Name::funcName(params...) [qualifiers]
# Groups:    1 = full qualifier  (e.g. "ZTUnit" or "Foo::Bar")
#            2 = bare func name  (e.g. "doFoodTrick")
#            3 = param string    (e.g. "unsigned short, unsigned short")
#            4 = trailing quals  (e.g. "const" -- may be absent)
_SIG_RE = re.compile(
    r'^(?:([\w:]+)::)?'          # optional qualifier  (group 1)
    r'([\w~<>]+)'                # bare function name  (group 2)
    r'\(([^)]*)\)'               # parameter list      (group 3)
    r'\s*(.*)$'                  # trailing qualifiers (group 4)
)


class ParsedSignature(object):
    """
    Holds the decomposed parts of a demangled C++ symbol.

    Attributes:
        full      (str) : The complete demangled signature as returned by
                          mw_demangle, e.g. "ZTUnit::doFoodTrick(unsigned short)"
        qualifier (str) : The class or namespace prefix, e.g. "ZTUnit" or
                          "Foo::Bar".  Empty string if there is none.
        bare_name (str) : The unqualified function name, e.g. "doFoodTrick".
        params    (str) : The raw parameter string, e.g. "unsigned short, int".
        trailing  (str) : Any trailing qualifiers such as "const".
    """
    def __init__(self, full, qualifier, bare_name, params, trailing):
        self.full      = full
        self.qualifier = qualifier
        self.bare_name = bare_name
        self.params    = params
        self.trailing  = trailing.strip()

    def comment_text(self):
        """Return the plate-comment string, e.g. '/* ZTUnit::doFoodTrick(...) */'"""
        return '/* {} */'.format(self.full)

    def __repr__(self):
        return ('ParsedSignature(qualifier={!r}, bare_name={!r}, '
                'params={!r}, trailing={!r})'.format(
                    self.qualifier, self.bare_name,
                    self.params, self.trailing))


def parse_signature(demangled):
    """
    Break a demangled Metrowerks signature into its component parts.

    Args:
        demangled (str): A fully demangled symbol such as
                         "ZTUnit::doFoodTrick(unsigned short, unsigned short)"
                         or "globalFunc(void)".

    Returns:
        ParsedSignature: The decomposed signature.

    Raises:
        ValueError: If *demangled* does not match the expected pattern.
    """
    # Strip a leading return type if present (a word followed by a space
    # before the qualified name).  e.g. "int Foo::bar(void)" -> "Foo::bar(void)"
    stripped = re.sub(r'^[\w:]+\s+(?=[\w:]+(?:::\w+)?\()', '', demangled).strip()

    m = _SIG_RE.match(stripped)
    if not m:
        raise ValueError("Cannot parse demangled signature: {!r}".format(demangled))

    qualifier = m.group(1) or ''
    bare_name = m.group(2)
    params    = m.group(3)
    trailing  = m.group(4) or ''

    return ParsedSignature(
        full      = demangled,
        qualifier = qualifier,
        bare_name = bare_name,
        params    = params,
        trailing  = trailing,
    )


# ---------------------------------------------------------------------------
#  Namespace / class helpers
# ---------------------------------------------------------------------------

def _get_or_create_namespace(ctx, qualifier):
    """
    Walk *qualifier* (e.g. "Foo::Bar::Baz") and return the innermost
    Ghidra Namespace, creating any missing levels as plain namespaces.

    Ghidra's createNameSpace API accepts a single component at a time, so
    we iterate the parts and nest them.

    Args:
        ctx       (GhidraContext): Shared Ghidra context.
        qualifier (str): A '::'-separated chain of namespace/class names.

    Returns:
        ghidra.program.model.symbol.Namespace
    """
    parts  = qualifier.split('::')
    parent = ctx.program.getGlobalNamespace()

    for part in parts:
        if not part:
            continue
        existing = ctx.symbol_table.getNamespace(part, parent)
        if existing is not None:
            parent = existing
        else:
            try:
                parent = ctx.symbol_table.createNameSpace(
                    parent, part, SourceType.ANALYSIS
                )
            except DuplicateNameException:
                # Race or pre-existing symbol with same name -- fetch it.
                parent = ctx.symbol_table.getNamespace(part, parent)
                if parent is None:
                    raise

    return parent


def _unique_name(ctx, namespace, base_name):
    """
    Return *base_name* if no symbol with that name exists in *namespace*,
    otherwise return None to signal that the caller must deduplicate.

    Args:
        ctx       (GhidraContext): Shared Ghidra context.
        namespace : Ghidra Namespace the function will land in.
        base_name (str): Desired function name.

    Returns:
        str or None
    """
    symbols = ctx.symbol_table.getSymbols(base_name, namespace)
    # Normalise iterator vs ArrayList (see run_on_debug_namespace for detail)
    try:
        has_any = symbols.hasNext()
    except AttributeError:
        has_any = len(list(symbols)) > 0
    return base_name if not has_any else None


# ---------------------------------------------------------------------------
#  Symbol collection helper
# ---------------------------------------------------------------------------

def _collect_symbols(symbol_iterable):
    """
    Normalise a Ghidra symbol collection to a plain Python list.

    Ghidra's getSymbols(Namespace) is overloaded and may return either a
    SymbolIterator (hasNext/next protocol) or a java.util.ArrayList (directly
    iterable in Jython but no hasNext).  This helper handles both.

    Args:
        symbol_iterable: A SymbolIterator or java.util.ArrayList from the
                         Ghidra symbol table API.

    Returns:
        list: Plain Python list of Symbol objects.
    """
    try:
        symbols = []
        while symbol_iterable.hasNext():
            symbols.append(symbol_iterable.next())
        return symbols
    except AttributeError:
        return list(symbol_iterable)


# ---------------------------------------------------------------------------
#  Per-function processing
# ---------------------------------------------------------------------------

def _set_plate_comment(ctx, func, comment_text):
    """
    Set (or replace) the plate comment on the first address of *func*.

    Plate comments appear as the banner above a function in the listing view.

    Args:
        ctx          (GhidraContext): Shared Ghidra context.
        func         : Ghidra Function object.
        comment_text (str): The full comment string including /* and */.
    """
    entry = func.getEntryPoint()
    ctx.listing.setComment(entry, CodeUnit.PLATE_COMMENT, comment_text)


def process_function(ctx, func):
    """
    Re-demangle, re-namespace, rename, and comment a single function.

    Steps
    -----
    1. Grab the current (possibly mangled) name.
    2. Ask mw_demangle to produce the best demangled form.
    3. Parse the signature to extract qualifier, bare name, and params.
    4. Get-or-create the target namespace.
    5. Move the function's symbol into that namespace.
    6. Rename the function to the bare (unqualified) name.
    7. Set a plate comment with the full signature.

    Args:
        ctx  (GhidraContext): Shared Ghidra context.
        func : Ghidra Function object from the '.debug' namespace.

    Returns:
        tuple: (status, message) where status is 'ok', 'skipped', or 'error'.
    """
    original_name = func.getName()

    # -- 1. Demangle --------------------------------------------------------
    try:
        demangled = mw_demangle.demangle_partial(original_name)
    except Exception as e:
        return ('error', "demangle failed on {!r}: {}".format(original_name, e))

    if demangled == original_name:
        # Nothing changed -- either already clean or unrecognised encoding.
        # We still process it if it looks like a qualified name so we can
        # at least move it into the right namespace.
        demangled = original_name

    # -- 2. Parse signature -------------------------------------------------
    try:
        sig = parse_signature(demangled)
    except ValueError as e:
        return ('skipped', str(e))

    # -- 3. Resolve / create target namespace -------------------------------
    if sig.qualifier:
        try:
            target_ns = _get_or_create_namespace(ctx, sig.qualifier)
        except Exception as e:
            return ('error', "namespace creation failed for {!r}: {}".format(
                sig.qualifier, e))
    else:
        target_ns = ctx.program.getGlobalNamespace()

    # -- 4. Determine a safe bare name -------------------------------------
    addr_str  = func.getEntryPoint().toString().replace(':', '_')
    safe_name = _unique_name(ctx, target_ns, sig.bare_name)
    deduped   = False
    if safe_name is None:
        safe_name = '{}_{}'.format(sig.bare_name, addr_str)
        deduped   = True

    # -- 5. Move symbol into target namespace ------------------------------
    primary_symbol = func.getSymbol()
    try:
        primary_symbol.setNamespace(target_ns)
    except DuplicateNameException:
        # Namespace move itself caused a collision -- force unique name now.
        if not deduped:
            safe_name = '{}_{}'.format(sig.bare_name, addr_str)
            deduped   = True
        try:
            primary_symbol.setNamespace(target_ns)
        except Exception as e:
            return ('error', "setNamespace failed for {!r}: {}".format(original_name, e))
    except Exception as e:
        return ('error', "setNamespace failed for {!r}: {}".format(original_name, e))

    # -- 6. Rename to bare name --------------------------------------------
    try:
        func.setName(safe_name, SourceType.ANALYSIS)
    except DuplicateNameException:
        safe_name = '{}_{}'.format(sig.bare_name, addr_str)
        deduped   = True
        try:
            func.setName(safe_name, SourceType.ANALYSIS)
        except Exception as e:
            return ('error', "setName failed for {!r}: {}".format(original_name, e))
    except Exception as e:
        return ('error', "setName failed for {!r}: {}".format(original_name, e))

    # -- 7. Plate comment --------------------------------------------------
    try:
        _set_plate_comment(ctx, func, sig.comment_text())
    except Exception as e:
        print("WARN: comment failed on {}: {}".format(safe_name, e))

    status_msg = "{} -> {}::{}{} [{}]".format(
        original_name,
        sig.qualifier or '<global>',
        safe_name,
        ' (deduped)' if deduped else '',
        sig.comment_text(),
    )
    return ('ok', status_msg)


# ---------------------------------------------------------------------------
#  Batch entry point
# ---------------------------------------------------------------------------

def run_on_debug_namespace(ctx):
    """
    Iterate every function whose primary symbol lives in the '.debug'
    namespace and apply process_function() to each one.

    A single Ghidra transaction wraps the entire batch so the operation
    is atomic and appears as one undo step.

    Args:
        ctx (GhidraContext): Shared Ghidra context.
    """
    debug_ns = ctx.symbol_table.getNamespace('.debug',
                                             ctx.program.getGlobalNamespace())
    if debug_ns is None:
        print("No '.debug' namespace found in this program.")
        return

    # Collect matching functions up front to avoid iterator invalidation
    # when we rename / re-namespace symbols mid-loop.
    target_funcs = []
    raw_symbols  = ctx.symbol_table.getSymbols(debug_ns)
    for sym in _collect_symbols(raw_symbols):
        if sym.getSymbolType() == SymbolType.FUNCTION:
            func = ctx.function_manager.getFunctionAt(sym.getAddress())
            if func is not None:
                target_funcs.append(func)

    if not target_funcs:
        print("No functions found in '.debug' namespace.")
        return

    print("Found {} function(s) in '.debug' namespace.".format(len(target_funcs)))

    tx = ctx.program.startTransaction("MW Organise Debug Namespace")
    ok_count      = 0
    skipped_count = 0
    error_count   = 0

    try:
        for func in target_funcs:
            status, message = process_function(ctx, func)
            if status == 'ok':
                print("OK:      {}".format(message))
                ok_count += 1
            elif status == 'skipped':
                print("SKIPPED: {}".format(message))
                skipped_count += 1
            else:
                print("ERROR:   {}".format(message))
                error_count += 1
    finally:
        ctx.program.endTransaction(tx, True)

    print("\n=== Organise Debug Namespace Complete ===")
    print("  Processed : {}".format(ok_count))
    print("  Skipped   : {}".format(skipped_count))
    print("  Errors    : {}".format(error_count))


# ---------------------------------------------------------------------------
#  Script entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Standalone execution from Script Manager.
    # Reconstruct a minimal GhidraContext from script-injected globals.
    class _StandaloneContext(object):
        def __init__(self):
            self.program           = currentProgram           # noqa: F821
            self.location          = currentLocation          # noqa: F821
            self.flat_api          = this                     # noqa: F821
            self.memory            = currentProgram.getMemory()
            self.function_manager  = currentProgram.getFunctionManager()
            self.symbol_table      = currentProgram.getSymbolTable()
            self.listing           = currentProgram.getListing()
            self.data_type_manager = currentProgram.getDataTypeManager()
            self.namespace_manager = currentProgram.getNamespaceManager()
            self.reference_manager = currentProgram.getReferenceManager()

    run_on_debug_namespace(_StandaloneContext())
