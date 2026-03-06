# Finds functions with undefined return types, decompiles them, and sets the
# return type to whatever the decompiler infers.
# @category Bryce
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SourceType

decomp_interface = DecompInterface()
decomp_interface.openProgram(currentProgram)

updated = 0
skipped = 0

for function in currentProgram.getFunctionManager().getFunctions(True):
    if function.getReturnType().getClass().getSimpleName() != "DefaultDataType":
        continue

    results = decomp_interface.decompileFunction(function, 30, ConsoleTaskMonitor())
    if not results.decompileCompleted():
        print("Skipped (decompile failed): {}".format(function.getName()))
        skipped += 1
        continue

    inferred_type = results.getHighFunction().getFunctionPrototype().getReturnType()

    if inferred_type.getClass().getSimpleName() == "DefaultDataType":
        print("Skipped (type still undefined): {}".format(function.getName()))
        skipped += 1
        continue

    function.setReturnType(inferred_type, SourceType.ANALYSIS)
    print("Updated: {} -> {}".format(function.getName(), inferred_type.getName()))
    updated += 1

print("\nDone. Updated: {}, Skipped: {}".format(updated, skipped))
