#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

import re
from ghidra.program.model.lang import OperandType, Register
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

from ExportASM import get_assembly, GhidraContext

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

def is_identified(function_name):
    return not function_name.startswith("FUN_00") \
        and not function_name.startswith("meth_0x") \
        and not function_name.startswith("virt_") \
        and not function_name.startswith("_") \
        and not function_name.startswith("cls_0x") \
        and not function_name.startswith("entry") \
        and not function_name.startswith("~cls_0") \
        and not function_name.startswith("ctor") \
        and not function_name.startswith("switchD") \
        and not function_name.startswith("lpLocaleEnumProc") \
        and not function_name.startswith("dtor_0x")

def get_functions():
    ctx = GhidraContext(currentProgram, currentLocation, currentProgram.getFunctionManager(), currentProgram.getSymbolTable())
    decomp_interface = DecompInterface()
    decomp_interface.openProgram(currentProgram)

    functions = ctx.function_manager.getFunctionsNoStubs(True)

    pure_functions = 0
    identified_pure_functions = 0
    more_likely_pure_functions = 0
    unidentified_pure_functions = 0
    uncalled_functions = 0
    uncalled_unidentified_functions = 0
    uncalled_pure_functions = 0
    total_functions = 0
    identified_functions = 0
    unidentified_functions = 0
    probably_empty_functions = 0

    fully_defined = 0
    unidentified_fully_defined = 0
    unidentified_fully_defined_at_least_one_call = 0

    i = 0
    i_bound = 99

    out_file = open("/Users/finnhartshorn/ghidra_scripts/pure_functions.txt", "w")
    out_file.write("Class, Name,Address,Size,Identified,Calling,Called,CalledAddresses,Pureish,CallersIdentified\n")
    function_out_dir = "/Users/finnhartshorn/Projects/zootycoon/ai-decompile/functions/"

    for function in functions:
        if function.isThunk():
            continue
        elif function.isExternal():
            continue
        total_functions += 1

        function_name = function.getName()
        function_class_name = get_class_name(function)
        identified = is_identified(function_name)
        callers_identified = all([is_identified(caller.getName()) for caller in function.getCalledFunctions(None)])
        called_by = function.getCallingFunctions(None)
        called = function.getCalledFunctions(None)
        if function.getBody().getNumAddresses() == 0 or function_name.startswith("null") or function_name.startswith("caseD_"):
            probably_empty_functions += 1
            continue
        if identified:
            identified_functions += 1
            if callers_identified:
                fully_defined += 1
                file_base = function_out_dir + function_class_name + "_" + function_name
                if function_class_name == " ":
                    file_base = function_out_dir + function_name
                if valid_file_name(file_base) and not excluded_function(function):
                    print("Writing out function: " + function_class_name + " " + function_name)
                    with open(file_base + ".asm", "w") as f:
                        f.write(get_assembly(ctx, function))
                    with open(file_base + ".c", "w") as f:
                        f.write(get_c_code(function, decomp_interface))
                    if len(called):
                        with open(file_base + ".meta", "w") as f:
                            f.write("\n".join(get_func_sigs(called)))
                else:
                    print("### Skipping function: " + function_class_name + " " + function_name)
            # In future we should be iterating through classes
        else:
            unidentified_functions += 1
            if len(called_by) == 0:
                uncalled_unidentified_functions += 1
            if callers_identified:
                unidentified_fully_defined += 1
                if len(called) > 0:
                    unidentified_fully_defined_at_least_one_call += 1
        
        more_likely_pure = False
        if len(called) == 0:
            pure_functions += 1
            if identified:
                identified_pure_functions += 1
                # print("Function %d: %s %s (%d)" % (i, get_class_name(function), function.getName(), function.getBody().getNumAddresses()))
                # if not function_name.startswith("get") and not function_name.startswith("set") and not function_name.startswith("is") and not function_name.startswith("dtor_") and not function_name.startswith("update") and not function_name.startswith("clear") and not function_name.startswith("force"):
                #     more_likely_pure_functions += 1
                #     more_likely_pure = True
                #     i += 1
                #     if i == i_bound:
                #         decomp_results = decomp_interface.decompileFunction(function, 0, ConsoleTaskMonitor())
                #         if decomp_results.decompileCompleted():
                #             decompiled_code = decomp_results.getDecompiledFunction().getC()
                #             print(decompiled_code)
            elif not identified:
                unidentified_pure_functions += 1
        
        if len(called_by) == 0:
            uncalled_functions += 1
        if len(called) == 0 and len(called_by) == 0:
            uncalled_pure_functions += 1

        out_file.write("\"%s\",\"%s\",0x%s,%d,%r,%d,%d,\"%s\",%r,%r\n" % (function_class_name, function.getName(), function.getEntryPoint().toString(), function.getBody().getNumAddresses(), identified, len(function.getCallingFunctions(None)), len(function.getCalledFunctions(None)), get_called_addresses(called), more_likely_pure, callers_identified))


    print("Found %d total functions" % total_functions)
    print("Found %d identified functions" % identified_functions)
    print("Found %d unidentified functions" % unidentified_functions)
    print("Found %d uncalled unidentified functions" % uncalled_unidentified_functions)
    print("Found %d probably empty functions" % probably_empty_functions)
    print("Found %d (potentially) pure functions" % pure_functions)
    print("Found %d more likely identified pure functions" % more_likely_pure_functions)
    print("Found %d identified (potentially) pure functions" % identified_pure_functions)
    print("Found %d unidentified (potentially)pure functions" % unidentified_pure_functions)
    print("Found %d uncalled (potentially) pure functions" % uncalled_pure_functions)
    print("Found %d uncalled functions" % uncalled_functions)
    print("Found %d fully defined functions" % fully_defined)
    print("Found %d unidentified fully defined functions" % unidentified_fully_defined)
    print("Found %d unidentified fully defined functions with at least one call" % unidentified_fully_defined_at_least_one_call)

def get_func_sigs(functions):
    sigs = []
    for f in functions:
        sigs.append(f.getPrototypeString(False, True))
    return sigs

def get_called_addresses(functions):
    if not functions:
        return ""
    return ",".join(["0x" + f.getEntryPoint().toString() for f in functions if not f.getEntryPoint().toString().startswith("EXTERNAL:")])

def excluded_function(function):
    return str(function.body.minAddress) in ["005349b0"]

def valid_file_name(file_name):
    return not " " in file_name \
        and not ">" in file_name \
        and not "<" in file_name \
        and not "." in file_name \
        and not "," in file_name \
        and not "?" in file_name \
        and not file_name.startswith("AI_")

def get_class_name(function):
    # Symbol currentFunctionSymbol = currentFunction.getSymbol();
	# 	Symbol parentSymbol = currentFunctionSymbol.getParentSymbol();
	#	String parentSymbolName;
    function_symbol = function.getSymbol()
    parent_symbol = function_symbol.getParentSymbol()
    parent_symbol_name = parent_symbol.getName()
    if parent_symbol_name == "global":
        parent_symbol_name = ""
    return parent_symbol_name
    

def get_c_code(function, decomp_interface):
    decomp_results = decomp_interface.decompileFunction(function, 0, ConsoleTaskMonitor())
    if decomp_results.decompileCompleted():
        return decomp_results.getDecompiledFunction().getC()
    return ""

if __name__ == "__main__":
    get_functions()
