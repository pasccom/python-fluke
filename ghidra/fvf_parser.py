# FVF (FlukeView File) parser
#@author 	Pascal Combes
#@category 	Data
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.data import DataTypeConflictHandler, CategoryPath
from ghidra.program.model.data import StructureDataType
from ghidra.program.model.data import WordDataType, DWordDataType
from ghidra.program.model.data import PointerDataType, StringDataType
from ghidra.program.model.listing import ProgramFragment
from ghidra.program.model.util import CodeUnitInsertionException

def createData(prog, addr, dataType):
    try:
        return prog.getListing().createData(addr, dataType)
    except CodeUnitInsertionException:
        prog.getListing().clearCodeUnits(addr, addr.add(dataType.getLength()), True, monitor)
        return prog.getListing().createData(addr, dataType)
	

def createFragment(prog, name, addr, size):
    for c in prog.getListing().getDefaultRootModule().getChildren():
        if (c.getName() == name):
            frag = c
            break
    else:
        frag = prog.getListing().getDefaultRootModule().createFragment(name)
    frag.move(addr, addr.add(size - 1))


# Search for the FVF file header:
if currentAddress is not None:
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'FV.FVF\x1A', None, True, monitor)
else:
    baseAddress = currentProgram.getMemory().findBytes(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0), 'FV.FVF\x1A', None, True, monitor)
if (baseAddress is None) and (currentAddress is not None):
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'FV.FVF\x1A', None, False, monitor)
if baseAddress is None:
    raise RuntimeError("Could not find CUR header")
print("Found FVF header at {}".format(baseAddress))

# Data type for FVF file header:
fvfHeaderType = StructureDataType(CategoryPath("/FVF"), "FVFHeader", 0)
fvfHeaderType.add(StringDataType.dataType, 8, 'magic', "FVF magic")
fvfHeaderType.add(WordDataType.dataType, 'version', "FVF version")
fvfHeaderType.add(DWordDataType.dataType, 'unused1', "Unused")
fvfHeaderType.add(DWordDataType.dataType, 'unused2', "Unused")
fvfHeaderType.add(DWordDataType.dataType, 'unused3', "Unused")
fvfHeaderType.add(WordDataType.dataType, 'sectorNumber', "Number of sectors in FVF file")
fvfHeaderType.add(DWordDataType.dataType, 'unused4', "Unused")
currentProgram.getDataTypeManager().addDataType(fvfHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for FVF sector header:
fvfSectorType = StructureDataType(CategoryPath("/FVF"), "FVFSector", 0)
fvfSectorType.add(PointerDataType.dataType, 'begin', "Sector begin")
fvfSectorType.add(DWordDataType.dataType, 'size', "Sector size")
fvfSectorType.add(WordDataType.dataType, 'index', "Sector index")
fvfSectorType.add(WordDataType.dataType, 'unused1', "Unused")
fvfSectorType.add(WordDataType.dataType, 'unused2', "Unused")
fvfSectorType.add(WordDataType.dataType, 'unused3', "Unused")
currentProgram.getDataTypeManager().addDataType(fvfSectorType, DataTypeConflictHandler.REPLACE_HANDLER)

# Parse FVF header:
fvfHeader = createData(currentProgram, baseAddress, fvfHeaderType)
version = fvfHeader.getComponent(1).getValue().getUnsignedValue()
print("FVF file version: {}".format(version))
if (version > 1):
    raise ValueError("Unsupported FVF file version")
sectorNumber = fvfHeader.getComponent(5).getValue().getUnsignedValue()
print("FVF file sectors: {}".format(sectorNumber))
createFragment(currentProgram, "FVF header", baseAddress, fvfHeaderType.getLength() + sectorNumber * fvfSectorType.getLength())

# Parse sector headers:
for s in range(0, sectorNumber):
    o = fvfHeaderType.getLength() + s * fvfSectorType.getLength()
    fvfSector = createData(currentProgram, baseAddress.add(o), fvfSectorType)
    begin = fvfSector.getComponent(0).getValue()
    size = fvfSector.getComponent(1).getValue().getUnsignedValue()
    index = fvfSector.getComponent(2).getValue().getUnsignedValue()
    print("Sector {}: b={} s={}".format(index, begin, size))
    createFragment(currentProgram, "FVF sector {}".format(index), baseAddress.add(begin.getOffset()), size)

# Clean empty fragments
for c in currentProgram.getListing().getDefaultRootModule().getChildren():
    try:    
        if c.isEmpty():
            currentProgram.getListing().getDefaultRootModule().removeChild(c.getName())
    except AttributeError:
        pass