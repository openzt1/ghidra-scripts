# ghidra_context.py
# Centralised Ghidra service container.  Construct once from the injected
# script globals and pass to every module function that needs Ghidra access.


class GhidraContext:
    """
    Wraps all Ghidra program services needed across vtable detection and
    application phases.  Constructed once in the driver script and passed
    explicitly to every function that needs Ghidra access, avoiding reliance
    on script-injected globals inside imported modules.

    Usage (in driver script):
        ctx = GhidraContext(currentProgram, currentLocation, this)
    """

    def __init__(self, current_program, current_location, flat_api):
        # Core program and cursor state
        self.program            = current_program
        self.location           = current_location

        # flat_api is the GhidraScript instance ('this' in the driver).
        # Provides toAddr(), getReferencesTo(), createFunction(), etc.
        self.flat_api           = flat_api

        # Derived program services -- cached for convenience
        self.memory             = current_program.getMemory()
        self.function_manager   = current_program.getFunctionManager()
        self.symbol_table       = current_program.getSymbolTable()
        self.listing            = current_program.getListing()
        self.data_type_manager  = current_program.getDataTypeManager()
        self.namespace_manager  = current_program.getNamespaceManager()
        self.reference_manager  = current_program.getReferenceManager()

        # Memory block partitions -- computed once, used throughout
        self.code_blocks        = [
            b for b in self.memory.getBlocks() if b.isExecute()
        ]
        self.data_blocks        = [
            b for b in self.memory.getBlocks() if not b.isExecute()
        ]
