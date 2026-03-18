# Metrowerks/CodeWarrior Symbol Re-Demangler for Ghidra
# Jython (Python 2) compatible
#
# Can be run standalone via Script Manager, or imported and called
# from another Ghidra script using the GhidraContext helper.
#
# Standalone:
#   Script Manager -> Run Script
#
# From another script:
#   import mw_demangle
#   mw_demangle.run_on_function(ctx, func)
#   mw_demangle.run_on_address(ctx, "0x12345678")
#   mw_demangle.run(ctx)   # re-demangle all functions
#
# @author   mw_demangle
# @category Analysis
# @menupath Analysis.Metrowerks Re-Demangle
# @toolbar
# @runtime Jython

import re

from ghidra.program.model.symbol import SourceType
from ghidra.app.script import GhidraScript
from ghidra.util.exception import DuplicateNameException


# ===========================================================================
#  Metrowerks / ARM C++ demangler  (Jython / Python 2 compatible)
# ===========================================================================

class MWDemangler(object):
    def __init__(self, symbol):
        s = symbol.strip()
        if s.startswith('.'):
            s = s[1:]
        if s.startswith('_') and not s.startswith('__'):
            s = s[1:]
        self.original = symbol
        self.s = s

    def demangle(self):
        s = self.s
        if '__' not in s:
            return self.original

        idx = s.find('__')
        if idx == -1:
            return self.original

        func_part = s[:idx]
        rest = s[idx+2:]

        qualifier, rest = self._parse_qualifier(rest)

        try:
            ret_type, params, qualifiers = self._parse_func_type(rest)
        except Exception:
            if qualifier:
                return qualifier + '::' + func_part + '(...)'
            return func_part + '(...)'

        param_str = ', '.join(params) if params else 'void'
        q_str = (' ' + qualifiers).rstrip() if qualifiers else ''

        if qualifier:
            return (ret_type + qualifier + '::' + func_part +
                    '(' + param_str + ')' + q_str).strip()
        else:
            return (ret_type + func_part +
                    '(' + param_str + ')' + q_str).strip()

    def _parse_qualifier(self, s):
        if not s:
            return '', s

        if s.startswith('Q'):
            s = s[1:]
            if not s or not s[0].isdigit():
                return '', s
            n = int(s[0])
            s = s[1:]
            parts = []
            for _ in range(n):
                name, s = self._parse_length_prefixed_name(s)
                parts.append(name)
            return '::'.join(parts), s
        elif s and s[0].isdigit():
            name, s = self._parse_length_prefixed_name(s)
            return name, s
        else:
            return '', s

    def _parse_length_prefixed_name(self, s):
        m = re.match(r'^(\d+)', s)
        if not m:
            return '', s
        length = int(m.group(1))
        s = s[m.end():]
        raw_name = s[:length]
        s = s[length:]
        decoded_name = self._decode_template_name(raw_name)
        return decoded_name, s

    def _decode_template_name(self, name):
        lt = name.find('<')
        if lt == -1:
            return name
        base = name[:lt]
        inner = name[lt+1:]
        if inner.endswith('>'):
            inner = inner[:-1]
        args = self._split_template_args(inner)
        decoded_args = [self._decode_template_arg(a.strip()) for a in args]
        return base + '<' + ', '.join(decoded_args) + '>'

    def _split_template_args(self, s):
        args = []
        depth = 0
        current = []
        for ch in s:
            if ch == '<':
                depth += 1
                current.append(ch)
            elif ch == '>':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args

    def _decode_template_arg(self, arg):
        if not arg:
            return arg
        if re.match(r'^-?\d+$', arg):
            return arg
        try:
            decoded, remainder = self._parse_type(arg)
            if len(remainder) <= 1:
                return decoded
        except Exception:
            pass
        return self._decode_template_name(arg)

    def _parse_func_type(self, s):
        qualifiers = []
        while s and s[0] in ('C', 'S', 'V'):
            if s[0] == 'C':
                qualifiers.append('const')
            elif s[0] == 'S':
                qualifiers.append('static')
            elif s[0] == 'V':
                qualifiers.append('volatile')
            s = s[1:]

        if not s or s[0] != 'F':
            return '', [], ' '.join(qualifiers)

        s = s[1:]
        params = []
        while s and s[0] != '_':
            typ, s = self._parse_type(s)
            if typ:
                params.append(typ)
            else:
                break

        ret_type = ''
        if s.startswith('_'):
            s = s[1:]
            if s:
                ret_type, _ = self._parse_type(s)

        ret_prefix = (ret_type + ' ') if ret_type else ''
        return ret_prefix, params, ' '.join(qualifiers)

    def _parse_type(self, s):
        if not s:
            return '', s

        c = s[0]

        if c == 'P':
            inner, s = self._parse_type(s[1:])
            return inner + '*', s
        if c == 'R':
            inner, s = self._parse_type(s[1:])
            return inner + '&', s
        if c == 'C':
            inner, s = self._parse_type(s[1:])
            return 'const ' + inner, s
        if c == 'V':
            inner, s = self._parse_type(s[1:])
            return 'volatile ' + inner, s
        if c == 'U':
            inner, s = self._parse_type(s[1:])
            return 'unsigned ' + inner, s

        fundamentals = {
            'v': 'void', 'c': 'char', 's': 'short', 'i': 'int',
            'l': 'long', 'f': 'float', 'd': 'double', 'r': 'long double',
            'b': 'bool', 'w': 'wchar_t', 'e': '...',
        }
        if c in fundamentals:
            return fundamentals[c], s[1:]

        if c == 'Q':
            name, s = self._parse_qualifier(s)
            return name, s
        if c.isdigit():
            name, s = self._parse_length_prefixed_name(s)
            return name, s
        if c == 'A':
            m = re.match(r'^A(\d+)_', s)
            if m:
                size = m.group(1)
                s = s[m.end():]
                inner, s = self._parse_type(s)
                return inner + '[' + size + ']', s
        if c == 'F':
            return 'func_ptr', s[1:]

        return c, s[1:]


# ===========================================================================
#  Partial / already-readable cleanup helpers
# ===========================================================================

def _decode_fragment(fragment):
    fragment = fragment.strip()
    if not fragment:
        return fragment
    d = MWDemangler(fragment)
    try:
        decoded, _ = d._parse_type(fragment)
        return decoded
    except Exception:
        return fragment


def _split_template_args(s):
    args = []
    depth = 0
    current = []
    for ch in s:
        if ch == '<':
            depth += 1
            current.append(ch)
        elif ch == '>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current))
    return args


def _decode_inner_args(s):
    args = _split_template_args(s)
    decoded = [_decode_fragment(a.strip()) for a in args]
    return ', '.join(decoded)


def _decode_template_args_in_readable(s):
    result = []
    i = 0
    while i < len(s):
        if s[i] == '<':
            depth = 1
            j = i + 1
            while j < len(s) and depth > 0:
                if s[j] == '<':
                    depth += 1
                elif s[j] == '>':
                    depth -= 1
                j += 1
            inner = s[i+1:j-1]
            result.append('<')
            result.append(_decode_inner_args(inner))
            result.append('>')
            i = j
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def _looks_mangled(s):
    s = s.strip()
    if ' ' in s:
        return False
    readable_starts = ('void', 'char', 'int', 'long', 'short', 'float',
                       'double', 'bool', 'unsigned', 'signed', 'const',
                       'volatile', 'struct', 'class', 'enum')
    if any(s.startswith(r) for r in readable_starts):
        return False
    if re.match(r'^[PRCUV][0-9A-Za-z]', s):
        return True
    if s and s[0].isdigit():
        return True
    if s.startswith('Q'):
        return True
    return False


def _decode_params_in_readable(s):
    m = re.search(r'\((.+)\)', s)
    if not m:
        return s

    inner = m.group(1)
    if inner.startswith('(') and inner.endswith(')'):
        inner = inner[1:-1]

    if inner == 'void' or not inner:
        return s[:m.start()] + '(' + inner + ')' + s[m.end():]

    args = _split_template_args(inner)
    decoded = []
    for arg in args:
        arg = arg.strip()
        if _looks_mangled(arg):
            decoded.append(_decode_fragment(arg))
        else:
            decoded.append(arg)

    return s[:m.start()] + '(' + ', '.join(decoded) + ')' + s[m.end():]


def demangle(symbol):
    try:
        return MWDemangler(symbol).demangle()
    except Exception:
        return symbol


def demangle_partial(symbol):
    """Main entry point: handles fully mangled, partially mangled, and clean symbols."""
    full = demangle(symbol)
    if full != symbol and '<' not in symbol:
        return full

    looks_readable = '::' in symbol or symbol.startswith('std::') or '~' in symbol
    if looks_readable:
        result = _decode_template_args_in_readable(symbol)
        result = _decode_params_in_readable(result)
        return result

    return full


def needs_redemangling(name):
    """
    Return True if the name still contains Metrowerks-style encodings
    that should be cleaned up.
    """
    if re.search(r'__Q\d', name):
        return True
    if re.search(r'<[PRCQUV]\d', name):
        return True
    if re.search(r'<\d+[A-Z]', name):
        return True
    if re.search(r'\([PRCQUV]\d', name):
        return True
    if re.search(r'\(\d+[A-Z]', name):
        return True
    if re.search(r',\s*[PRCQUV]\d', name):
        return True
    if re.search(r',\s*\d+[A-Z]', name):
        return True
    return False


# ===========================================================================
#  Name validation
# ===========================================================================

class DemangleError(Exception):
    """Raised when a symbol name is not eligible for re-demangling."""
    pass


def validate_symbol_name(name):
    """
    Raise DemangleError if the name contains characters that indicate it has
    already been demangled or is otherwise ineligible for processing.

    Ghidra symbol names with spaces or angle brackets are already in a
    human-readable / C++ decorated form that we must not corrupt by
    re-running the mangled-name parser over them.

    Args:
        name (str): The raw symbol name from Ghidra.

    Raises:
        DemangleError: with a descriptive message if the name is ineligible.
    """
    if ' ' in name:
        raise DemangleError(
            "Symbol '{}' contains spaces -- already demangled or decorated; "
            "skipping.".format(name)
        )
    if '<' in name or '>' in name:
        raise DemangleError(
            "Symbol '{}' contains angle brackets -- already demangled or "
            "decorated; skipping.".format(name)
        )


# ===========================================================================
#  Core rename logic (shared by all entry points)
# ===========================================================================

def _apply_rename(program, func, new_name):
    """
    Rename *func* to *new_name* inside an already-open transaction.
    Appends the entry-point address on a DuplicateNameException.

    Returns the final name that was applied.
    """
    try:
        func.setName(new_name, SourceType.ANALYSIS)
        return new_name
    except DuplicateNameException:
        addr_str = func.getEntryPoint().toString().replace(':', '_')
        unique_name = '{}_{}'.format(new_name, addr_str)
        func.setName(unique_name, SourceType.ANALYSIS)
        return unique_name


def _process_one(program, func):
    """
    Attempt to re-demangle a single function.

    Validates, checks whether redemangling is needed, demangling, and
    applies the rename.  All within an already-open transaction.

    Returns a tuple (status, original_name, final_name) where status is
    one of: 'renamed', 'renamed_deduped', 'skipped', 'skipped_invalid',
    'error'.
    """
    original_name = func.getName()

    # Reject already-decoded or decorated names.
    try:
        validate_symbol_name(original_name)
    except DemangleError as e:
        return ('skipped_invalid', original_name, str(e))

    if not needs_redemangling(original_name):
        return ('skipped', original_name, original_name)

    try:
        new_name = demangle_partial(original_name)
        if not new_name or new_name == original_name:
            return ('skipped', original_name, original_name)

        final_name = _apply_rename(program, func, new_name)
        status = 'renamed' if final_name == new_name else 'renamed_deduped'
        return (status, original_name, final_name)

    except Exception as e:
        return ('error', original_name, str(e))


# ===========================================================================
#  Public API -- callable from other Ghidra scripts
# ===========================================================================

def run_on_function(ctx, func):
    """
    Re-demangle a single Ghidra Function object.

    Intended to be called from another script that already holds a
    GhidraContext.  Opens its own transaction so it is safe to call
    without an enclosing transaction.

    Args:
        ctx  (GhidraContext): The shared Ghidra context from the driver script.
        func (ghidra.program.model.listing.Function): The function to process.

    Returns:
        tuple: (status, original_name, final_name_or_message)
            status is one of: 'renamed', 'renamed_deduped', 'skipped',
            'skipped_invalid', 'error'.

    Example (from another script)::

        import mw_demangle
        result = mw_demangle.run_on_function(ctx, some_func)
        if result[0].startswith('renamed'):
            print("Renamed: {} -> {}".format(result[1], result[2]))
    """
    tx = ctx.program.startTransaction("MW Re-Demangle: single function")
    try:
        result = _process_one(ctx.program, func)
    finally:
        ctx.program.endTransaction(tx, True)

    status, original, final = result
    if status == 'renamed':
        print("RENAMED: {} -> {}".format(original, final))
    elif status == 'renamed_deduped':
        print("RENAMED (deduped): {} -> {}".format(original, final))
    elif status == 'skipped_invalid':
        print("SKIPPED (invalid): {}".format(final))
    elif status == 'error':
        print("ERROR on {}: {}".format(original, final))

    return result


def run_on_address(ctx, address):
    """
    Re-demangle the function at the given address.

    Args:
        ctx     (GhidraContext): The shared Ghidra context from the driver script.
        address: A Ghidra Address object *or* an address string such as
                 "0x12345678" or "ram:12345678".

    Returns:
        tuple: Same (status, original_name, final_name_or_message) as
               run_on_function(), or ('error', str(address), message) if no
               function exists at that address.

    Example (from another script)::

        import mw_demangle
        result = mw_demangle.run_on_address(ctx, "0x00123456")
    """
    # Accept either a raw Address or a string.
    if isinstance(address, str):
        address = ctx.flat_api.toAddr(address)

    func = ctx.function_manager.getFunctionAt(address)
    if func is None:
        msg = "No function found at address {}".format(address)
        print("ERROR: " + msg)
        return ('error', str(address), msg)

    return run_on_function(ctx, func)


def run(ctx=None):
    """
    Re-demangle all functions in the program.

    Can be called in two ways:

    1. Standalone (no argument) -- uses Ghidra's script-injected globals
       ``currentProgram`` and is executed when the script is run directly
       from the Script Manager.

    2. From another script -- pass a GhidraContext to avoid relying on
       injected globals::

           import mw_demangle
           mw_demangle.run(ctx)

    Args:
        ctx (GhidraContext or None): If None, falls back to the
            script-global ``currentProgram``.
    """
    if ctx is not None:
        program        = ctx.program
        function_manager = ctx.function_manager
    else:
        # Standalone / Script Manager execution -- globals injected by Ghidra.
        program          = currentProgram          # noqa: F821
        function_manager = program.getFunctionManager()

    functions = function_manager.getFunctions(True)

    tx = program.startTransaction("MW Re-Demangle")
    renamed = 0
    skipped = 0
    errors  = 0

    try:
        func = functions.next() if functions.hasNext() else None
        while func is not None:
            status, original, final = _process_one(program, func)

            if status == 'renamed':
                print("RENAMED: {} -> {}".format(original, final))
                renamed += 1
            elif status == 'renamed_deduped':
                print("RENAMED (deduped): {} -> {}".format(original, final))
                renamed += 1
            elif status == 'skipped_invalid':
                print("SKIPPED (invalid): {}".format(final))
                skipped += 1
            elif status == 'error':
                print("ERROR on {}: {}".format(original, final))
                errors += 1
            else:
                skipped += 1

            func = functions.next() if functions.hasNext() else None

    finally:
        program.endTransaction(tx, True)

    print("\n=== MW Re-Demangle Complete ===")
    print("  Renamed : {}".format(renamed))
    print("  Skipped : {}".format(skipped))
    print("  Errors  : {}".format(errors))


# ===========================================================================
#  Script entry point -- only executes when run directly from Script Manager
# ===========================================================================

if __name__ == '__main__':
    run()
