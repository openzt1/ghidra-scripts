#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


import re
# from ghidra.program.model.lang import OperandType, Register
from ghidra.program.database.data import StructureDB, PointerDB
# from ghidra.app.decompiler import DecompInterface
# from ghidra.util.task import ConsoleTaskMonitor

from ExportASM import GhidraContext

try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    from ghidra.ghidra_builtins import *


def get_function_at_offset(ctx, offset):
    pass
    # function = ctx.function_manager.getFunctionContaining(offset)
    # if function is None:
    #     return None
    # if not is_identified(function.getName()):
    #     return None
    # return function


def get_function(ctx, addr):
    func = ctx.function_manager.getFunctionContaining(toAddr(addr))
    if func is None:
        print("No function found at the current location.")
    elif func.isThunk():
        print("Function is a thunk.")
    elif func.isExternal():
        print("Function is external.")
    else:
        return func
    return None


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
    "ZTStaff",
    "ZTKeeper",
    "ZTMaint",
    "ZTGuide",
    "ZTHelicopter",
    "ZTAmbient",
    "ZTRubble",
    "ZTTankWall",
    "ZTTankFilter",
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
    "ZTStaffType",
    "ZTKeeperType",
    "ZTMaintType",
    "ZTGuideType",
    "ZTHelicopterType",
    "ZTAmbientType",
    "ZTRubbleType",
    "ZTTankWallType",
    "ZTTankFilterType",
]

if __name__ == "__main__":
    ctx = GhidraContext(currentProgram, currentLocation, currentProgram.getFunctionManager(), currentProgram.getSymbolTable())
    types_or_entities = askChoice("Find VTable Offsets", "Entity or Entity Types", ["Entity", "Entity Types"], 0)
    if types_or_entities == "Entity":
        class_names = entity_names
    elif types_or_entities == "Entity Types":
        class_names = entity_type_names
    else:
        print("Invalid choice.")
        exit(1)
    addr = askAddress("Vtable Offset", "Enter Vtable offset (e.g. 0x1c):")
    print("Answer: ", addr, addr.getOffset())
    for datatype in currentProgram.getDataTypeManager().getAllDataTypes():
        parts = datatype.getName().split("::")
        # print(parts)
        if len(parts) > 1 and parts[0] in class_names and (parts[1].startswith("vftable") or parts[1].startswith("vtable")) and type(datatype) is StructureDB:
            # print(datatype.getName()) 
            f = datatype.getComponentAt(addr.getOffset())
            if f is None:
                print("No datatype: " + parts[0])
                continue
            if f.getDataType() is None or type(f.getDataType()) is not PointerDB:
                print("No pointer: " + str(type(f.getDataType())) + " " + parts[0]) 
                continue
            if f.getDataType().getDataType() is None:
                print("Void ptr?: " + parts[0])
                continue
            function_address = f.getDataType().getDataType().getName().split("_")[-1]
            print(parts[0] + " " + function_address + " " + get_function(ctx, function_address).getName())
            # print(parts[0] + " " + f.getDataType().getName() + " " + f.getDataType().getDataType().getName())
            # print(datatype.getDefinedComponents()
        # elif len(parts) > 1 and parts[0].split("_")[0] not in ["virt", "~cls", "cls"]:
        #     print(parts[0])
