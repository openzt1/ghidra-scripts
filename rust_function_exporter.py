# Exports identified functions as Rust function definitions organized by class
# @category Rust
# @runtime Jython

import re
import os
from collections import defaultdict

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


# Custom type mappings - Add your game-specific type mappings here
# Format: "GhidraTypeName": "RustTypeName"
# Example: "BFPos": "IVec3"
# Note: Pointer handling is automatic - if you map "BFPos" to "IVec3",
#       then "BFPos*" will automatically map to "*mut IVec3" or "*const IVec3"
CUSTOM_TYPE_MAP = {
    # Add your custom mappings below:
    # "BFPos": "IVec3",
    # "BFVec3": "Vec3",
    # "BfResourceMgr": "ResourceMgr",
    # "std::string": "String",
}


def is_identified(function_name):
    """Check if a function has been properly identified (not a default Ghidra name)"""
    return not function_name.startswith("FUN_00") \
        and not function_name.startswith("fun_00") \
        and not function_name.startswith("meth_0x") \
        and not function_name.startswith("virt_") \
        and not function_name.startswith("_") \
        and not function_name.startswith("cls_0x") \
        and not function_name.startswith("entry") \
        and not function_name.startswith("~cls_0") \
        and not function_name.startswith("ctor") \
        and not function_name.startswith("switchD") \
        and not function_name.startswith("switchd") \
        and not function_name.startswith("lpLocaleEnumProc") \
        and not function_name.startswith("dtor_0x") \
        and not function_name.startswith("thunk_FUN_")

def get_class_name(function):
    """Get the class name from the function's symbol hierarchy, including namespace"""
    function_symbol = function.getSymbol()
    parent_symbol = function_symbol.getParentSymbol()
    parent_symbol_name = parent_symbol.getName()
    
    # Return None to indicate this function should be excluded
    if parent_symbol_name and parent_symbol_name.startswith("switchD"):
        return None
    
    # Check if we should look one level up for namespace
    if parent_symbol_name and parent_symbol_name != "global":
        grandparent_symbol = parent_symbol.getParentSymbol()
        if grandparent_symbol:
            grandparent_name = grandparent_symbol.getName()
            # Only prepend if it's not one of the excluded names
            if grandparent_name and grandparent_name not in ["global", "OOAnalyzer"]:
                # Also exclude if grandparent starts with 'switchD'
                if grandparent_name.startswith("switchD"):
                    return None
                # Combine namespace::class
                parent_symbol_name = "{}::{}".format(grandparent_name, parent_symbol_name)
    
    if parent_symbol_name == "global":
        parent_symbol_name = ""
    
    return parent_symbol_name

def load_mutability_config(config_file="mutability.cfg"):
    """
    Load mutability configuration from a file.

    File format (one function per line):
        # Comments start with #
        ClassName::FunctionName 0 2 3  # params at indices 0, 2, 3 are mutable
        standalone::FunctionName 1     # param at index 1 is mutable

    Returns a dict mapping "ClassName::FunctionName" -> set of mutable param indices
    """
    mutability_map = {}

    try:
        with open(config_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                # Strip whitespace and skip comments/empty lines
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Split line into parts
                parts = line.split()
                if len(parts) < 1:
                    continue

                function_name = parts[0]

                # Parse parameter indices (rest of the line)
                mutable_indices = set()
                for part in parts[1:]:
                    # Skip inline comments
                    if part.startswith("#"):
                        break
                    try:
                        mutable_indices.add(int(part))
                    except ValueError:
                        print("Warning: Invalid parameter index '{}' on line {} in {}".format(
                            part, line_num, config_file))

                mutability_map[function_name] = mutable_indices

        print("Loaded mutability config for {} functions from {}".format(
            len(mutability_map), config_file))
    except IOError:
        print("No mutability config file found at {}. All pointers will be *const.".format(
            config_file))

    return mutability_map

def get_calling_convention(function):
    """Determine the calling convention from function signature"""
    signature = function.getSignature()
    calling_conv = signature.getCallingConventionName()

    # Map Ghidra conventions to Rust conventions
    if calling_conv == "__thiscall":
        return "thiscall"
    elif calling_conv == "__stdcall":
        return "stdcall"
    elif calling_conv == "__fastcall":
        return "fastcall"
    elif calling_conv == "__cdecl" or calling_conv == "default":
        return "cdecl"
    else:
        return "cdecl"  # Default to cdecl if unknown

def map_type_to_rust(ghidra_type, is_mutable=False, _debug_fn=None):
    """Map Ghidra types to Rust types"""
    if _debug_fn:
        type_display_debug = str(ghidra_type)
        is_ptr_debug = "*" in type_display_debug or "*" in ghidra_type.getName()
        print("DEBUG map_type_to_rust [{}]: getName={!r}, str={!r}, class={!r}, is_pointer={!r}".format(
            _debug_fn, ghidra_type.getName(), type_display_debug,
            ghidra_type.getClass().getSimpleName(), is_ptr_debug
        ))

    # Handle void type explicitly - check the actual type name
    if ghidra_type.getName() == "void":
        return "()"

    # Basic type mappings as ordered list - more specific entries must come before
    # general ones to avoid "undefined" matching "undefined4", etc.
    type_map = [
        ("ulonglong", "u64"),
        ("longlong", "i64"),
        ("undefined8", "u64"),
        ("undefined4", "u32"),
        ("undefined2", "u16"),
        ("undefined1", "u8"),
        ("undefined", "u8"),
        ("ulong", "u32"),
        ("uint", "u32"),
        ("ushort", "u16"),
        ("uchar", "u8"),
        ("ubyte", "u8"),
        ("bool", "bool"),
        ("char", "i8"),
        ("byte", "u8"),
        ("short", "i16"),
        ("int", "i32"),
        ("long", "i32"),
        ("float", "f32"),
        ("double", "f64"),
    ]

    # Detect pointer types via string representation - more reliable than isinstance in Jython
    type_display = str(ghidra_type)
    is_pointer = "*" in type_display or "*" in ghidra_type.getName()

    if is_pointer:
        mutability = "mut" if is_mutable else "const"
        # Try getDataType() for clean base type name, fall back to string stripping
        try:
            base_type_str = ghidra_type.getDataType().getName().replace(" ", "")
        except Exception:
            base_type_str = type_display.replace("*", "").replace(" ", "")

        # Handle void and LPVOID (Windows typedef for void *)
        base_type_clean = base_type_str.replace("*", "").strip()
        if base_type_clean == "void" or base_type_clean.upper() == "LPVOID":
            return "*{} c_void".format(mutability)

        # Check custom type mapping for base type first
        base_type_clean = base_type_str.replace("*", "")
        if base_type_clean in CUSTOM_TYPE_MAP:
            custom_rust_type = CUSTOM_TYPE_MAP[base_type_clean]
            return "*{} {}".format(mutability, custom_rust_type)

        # Exact match first, then substring (list order ensures specificity)
        base_type_str_lower = base_type_str.lower()
        for ghidra_key, rust in type_map:
            if base_type_str_lower == ghidra_key:
                return "*{} {}".format(mutability, rust)
        for ghidra_key, rust in type_map:
            if ghidra_key in base_type_str_lower:
                return "*{} {}".format(mutability, rust)

        return "*{} u32".format(mutability)

    # Check custom type mapping first
    type_str = ghidra_type.getName()
    if type_str in CUSTOM_TYPE_MAP:
        return CUSTOM_TYPE_MAP[type_str]

    type_str_lower = type_str.lower()

    # Exact match first, then substring
    for ghidra_key, rust in type_map:
        if type_str_lower == ghidra_key:
            return rust
    for ghidra_key, rust in type_map:
        if ghidra_key in type_str_lower:
            return rust

    return "u32"

def get_function_signature_rust(function, class_name=None, mutability_map=None):
    """Generate Rust function signature from Ghidra function"""
    signature = function.getSignature()
    params = signature.getArguments()
    return_type = signature.getReturnType()
    calling_conv = get_calling_convention(function)

    if mutability_map is None:
        mutability_map = {}

    # Determine function lookup keys for mutability config
    fn_name = function.getName()
    lookup_keys = [fn_name]  # Try just the function name
    if class_name:
        # Also try with class prefix
        lookup_keys.insert(0, "{}::{}".format(class_name, fn_name))

    # Find mutable parameter indices
    mutable_params = set()
    for key in lookup_keys:
        if key in mutability_map:
            mutable_params = mutability_map[key]
            break

    debug = fn_name if fn_name.startswith("CreateZT") else None

    # Map parameter types
    param_types = []
    for i, param in enumerate(params):
        is_mutable = i in mutable_params
        rust_type = map_type_to_rust(param.getDataType(), is_mutable, _debug_fn=debug)
        param_types.append(rust_type)

    # Handle 'this' parameter for thiscall
    if calling_conv == "thiscall" and len(param_types) > 0:
        # First parameter is implicit 'this', but we still include it in Rust
        pass

    # Map return type
    return_type_name = return_type.getName()
    if debug:
        direct_rt = function.getReturnType()
        print("DEBUG return: fn={!r}, sig getName={!r}, direct getName={!r}, direct str={!r}, direct class={!r}".format(
            fn_name, return_type_name,
            direct_rt.getName(), str(direct_rt), direct_rt.getClass().getSimpleName()
        ))
    if return_type_name in ("void", "undefined"):
        rust_return = "()"
    else:
        rust_return = map_type_to_rust(return_type, _debug_fn=debug)
    if debug:
        print("DEBUG return: fn={!r} -> rust_return={!r}".format(fn_name, rust_return))

    # Build the function type string
    if len(param_types) == 0:
        params_str = "()"
    else:
        params_str = "(" + ", ".join(param_types) + ")"

    if rust_return == "()":
        fn_type = "unsafe extern \"{}\" fn{}".format(calling_conv, params_str)
    else:
        fn_type = "unsafe extern \"{}\" fn{} -> {}".format(calling_conv, params_str, rust_return)

    return fn_type

def sanitize_class_name(class_name):
    """Sanitize class name for use as a Rust module name"""
    # Remove angle brackets and other invalid characters
    class_name = class_name.replace("<", "").replace(">", "")
    
    # Handle namespace::class format by replacing :: with _
    class_name = class_name.replace("::", "_")
    
    # Convert to lowercase and replace non-alphanumeric with underscores
    result = ""
    for char in class_name:
        if char.isalnum():
            result += char.lower()
        else:
            result += "_"
    
    # Remove duplicate underscores
    while "__" in result:
        result = result.replace("__", "_")
    result = result.strip("_")
    
    # If it starts with a number, prepend "class_"
    if result and result[0].isdigit():
        result = "class_" + result
    
    return result if result else "unnamed"

def sanitize_rust_name(name, class_name=""):
    """Convert function name to valid Rust constant name"""
    original_name = name
    
    # Remove angle brackets (template parameters)
    name = name.replace("<", "").replace(">", "")
    
    # Remove class prefix if it exists in the function name
    if "::" in name:
        name = name.split("::")[-1]
    
    # Handle constructor case - if the name matches the class name exactly
    is_constructor = False
    if class_name and name.upper() == class_name.upper().replace("::", "_"):
        is_constructor = True
        result = "CONSTRUCTOR"
    else:
        # If the function name starts with the class name, remove it
        if class_name and name.upper().startswith(class_name.upper()):
            # Remove the class prefix and any following underscore
            name = name[len(class_name):]
            if name.startswith("_"):
                name = name[1:]
        
        # Convert to uppercase with underscores
        result = ""
        for i, char in enumerate(name):
            if i > 0 and char.isupper() and name[i-1].islower():
                result += "_"
            result += char.upper() if char.isalnum() else "_"
        
        # Remove duplicate underscores and trailing underscores
        while "__" in result:
            result = result.replace("__", "_")
        result = result.strip("_")
    
    # Handle special cases for empty results
    if not result:
        if is_constructor:
            result = "CONSTRUCTOR"
        elif "destructor" in original_name.lower() or original_name.startswith("~"):
            result = "DESTRUCTOR"
        else:
            result = "UNKNOWN_METHOD"
    
    # If result starts with a number, prepend "FN_"
    if result and result[0].isdigit():
        result = "FN_" + result
    
    return result

def main():
    # Load mutability configuration
    mutability_map = load_mutability_config("mutability.cfg")

    # Get all functions
    function_manager = currentProgram.getFunctionManager()
    functions = function_manager.getFunctions(True)

    # Group functions by class
    class_functions = defaultdict(list)
    standalone_functions = []

    print("Analyzing functions...")
    function_count = 0
    identified_count = 0
    
    for function in functions:
        function_count += 1
        name = function.getName()
        
        # Skip unidentified functions
        if not is_identified(name):
            continue
            
        identified_count += 1
        
        # Get class name from symbol hierarchy
        class_name = get_class_name(function)
        
        # Skip functions in excluded classes (returns None)
        if class_name is None:
            identified_count -= 1  # Don't count excluded functions
            continue
        
        if class_name and class_name != "":
            class_functions[class_name].append(function)
        else:
            standalone_functions.append(function)
    
    print("Found {} identified functions out of {} total".format(identified_count, function_count))
    print("Classes found: {}".format(len(class_functions)))
    
    # Generate Rust code
    rust_code = []
    rust_code.append("// Auto-generated Rust function definitions for Zoo Tycoon")
    rust_code.append("// Generated from Ghidra analysis")
    rust_code.append("")
    rust_code.append("#![allow(clippy::type_complexity)]")
    rust_code.append("")
    rust_code.append("use std::marker::PhantomData;")
    rust_code.append("use core::ffi::c_void;")
    rust_code.append("")
    rust_code.append("use crate::FunctionDef;")
    rust_code.append("")
    rust_code.append("#[cfg(feature = \"detour-validation\")]")
    rust_code.append("use openzt_detour_macro::validate_detour;")
    rust_code.append("")
    
    # Generate class-organized functions
    for class_name in sorted(class_functions.keys()):
        sanitized_module_name = sanitize_class_name(class_name)
        rust_code.append("// {} class functions".format(class_name))
        rust_code.append("pub mod {} {{".format(sanitized_module_name))
        rust_code.append("    use super::*;")
        rust_code.append("")
        
        # Sort functions by address for deterministic ordering
        sorted_functions = sorted(class_functions[class_name], key=lambda f: f.getEntryPoint().getOffset())
        
        # Track name counts for handling duplicates
        name_counts = {}
        name_indices = {}
        
        # First pass: count occurrences of each name
        for function in sorted_functions:
            fn_name = function.getName()
            rust_const_name = sanitize_rust_name(fn_name, class_name)
            
            if rust_const_name:
                full_const_name = rust_const_name
            else:
                full_const_name = "{}_METHOD".format(class_name.upper())
            
            if full_const_name not in name_counts:
                name_counts[full_const_name] = 0
                name_indices[full_const_name] = 0
            name_counts[full_const_name] += 1
        
        # Second pass: generate code with numbered duplicates
        for function in sorted_functions:
            fn_name = function.getName()
            rust_const_name = sanitize_rust_name(fn_name, class_name)
            
            if rust_const_name:
                base_const_name = rust_const_name
            else:
                base_const_name = "{}_METHOD".format(class_name.upper())
            
            # Add number suffix if there are duplicates
            if name_counts[base_const_name] > 1:
                full_const_name = "{}_{}".format(base_const_name, name_indices[base_const_name])
                name_indices[base_const_name] += 1
            else:
                full_const_name = base_const_name
            
            try:
                fn_signature = get_function_signature_rust(function, class_name, mutability_map)
                address = function.getEntryPoint().getOffset()

                rust_code.append("    #[cfg_attr(feature = \"detour-validation\", validate_detour(\"{}/{}\"))]"
                    .format(sanitized_module_name, full_const_name.lower()))
                rust_code.append("    pub const {}: FunctionDef<{}> = FunctionDef{{address: {:#010x}, function_type: PhantomData}};".format(
                    full_const_name, fn_signature, address))
            except Exception as e:
                print("Warning: Could not process function {}: {}".format(fn_name, str(e)))
                continue

        rust_code.append("}")
        rust_code.append("")

    # Generate standalone functions
    if standalone_functions:
        rust_code.append("// Standalone functions")
        rust_code.append("pub mod standalone {")
        rust_code.append("    use super::*;")
        rust_code.append("")
        
        # Sort functions by address for deterministic ordering
        sorted_functions = sorted(standalone_functions, key=lambda f: f.getEntryPoint().getOffset())
        
        # Track name counts for handling duplicates
        name_counts = {}
        name_indices = {}
        
        # First pass: count occurrences of each name
        for function in sorted_functions:
            fn_name = function.getName()
            rust_const_name = sanitize_rust_name(fn_name)
            
            if rust_const_name not in name_counts:
                name_counts[rust_const_name] = 0
                name_indices[rust_const_name] = 0
            name_counts[rust_const_name] += 1
        
        # Second pass: generate code with numbered duplicates
        for function in sorted_functions:
            fn_name = function.getName()
            base_const_name = sanitize_rust_name(fn_name)

            # Add number suffix if there are duplicates
            if name_counts[base_const_name] > 1:
                full_const_name = "{}_{}".format(base_const_name, name_indices[base_const_name])
                name_indices[base_const_name] += 1
            else:
                full_const_name = base_const_name

            try:
                fn_signature = get_function_signature_rust(function, None, mutability_map)
                address = function.getEntryPoint().getOffset()

                rust_code.append("    #[cfg_attr(feature = \"detour-validation\", validate_detour(\"standalone/{}\"))]"
                    .format(full_const_name.lower()))
                rust_code.append("    pub const {}: FunctionDef<{}> = FunctionDef{{address: {:#010x}, function_type: PhantomData}};".format(
                    full_const_name, fn_signature, address))
            except Exception as e:
                print("Warning: Could not process function {}: {}".format(fn_name, str(e)))
                continue
        
        rust_code.append("}")
    
    # Write to file
    output_file = str(currentProgram.getExecutablePath()).replace(".exe", "_functions.rs")
    output_file = output_file.replace("\\", "/")
    if "/" in output_file:
        output_file = output_file.split("/")[-1]
    
    print("\nWriting to {} at {}".format(output_file, os.getcwd()))
    
    with open(output_file, 'w') as f:
        f.write("\n".join(rust_code))
    
    print("Successfully exported {} identified functions to {}".format(identified_count, output_file))
    print("\nExample usage in Rust:")
    print("  use {}_functions::*;".format(output_file.replace("_functions.rs", "")))
    print("  let mgr_constructor = bfresourcemgr::BFRESOURCEMGR_CONSTRUCTOR;")

if __name__ == "__main__":
    main()
