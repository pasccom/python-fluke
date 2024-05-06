# FVS file parser
#@author    Pascal COMBES
#@category  Data
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.data import DataTypeConflictHandler, CategoryPath,\
	Undefined8DataType
from ghidra.program.model.data import ArrayDataType, StructureDataType
from ghidra.program.model.data import StringDataType
from ghidra.program.model.data import ByteDataType, WordDataType, DWordDataType
from ghidra.program.model.symbol import RefType
from ghidra.program.model.util import CodeUnitInsertionException

# FVS sector types:
#  - 0x10 Main sector
#  - 0x11 Main sector continuation?
#  - 0x18 Main sector
#  - 0x19 Main sector
#  - 0x20 Date and time
#  - 0x30 EPS1
#  - 0x31 EPS2
#  - 0x32 HGL
#  - 0x33 FV
#  - 0x50 
#  - 0x51 
#  - 0x52 Flags, Colors, caption, ...
#  - 0x60 Description

# Flags
#  - 0x0001 DescrOn
#  - 0x0008 DbOn

def createData(prog, addr, dataType):
    try:
        return prog.getListing().createData(addr, dataType)
    except CodeUnitInsertionException:
        prog.getListing().clearCodeUnits(addr, addr.add(max(1, dataType.getLength() - 1)), True, monitor)
        return prog.getListing().createData(addr, dataType)


def createFragment(prog, name, addr, size):
    for c in prog.getListing().getDefaultRootModule().getChildren():
        if (c.getName() == name):
            frag = c
            break
    else:
        frag = prog.getListing().getDefaultRootModule().createFragment(name)
    frag.move(addr, addr.add(size - 1))


def createRefs(data, addr):
    for dataTypeComponent in data.getDataType().getComponents():
        if not dataTypeComponent.getFieldName().startswith('offset'):
            continue
        component = data.getComponent(dataTypeComponent.getOrdinal())
        offset = component.getValue().getUnsignedValue()
        if (offset != 0):
            component.addValueReference(addr.add(offset), RefType.DATA)


# Search for the FVS file header:
if currentAddress is not None:
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'FV.FVS\x1A', None, True, monitor)
else:
    baseAddress = currentProgram.getMemory().findBytes(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0), 'FV.FVS\x1A', None, True, monitor)
if (baseAddress is None) and (currentAddress is not None):
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'FV.FVS\x1A', None, False, monitor)
if (baseAddress is None):
    raise RuntimeError("Could not find FVS header")
print("Found FVS header at {}".format(baseAddress))

# Data type for FVS file header:
fvsHeaderType = StructureDataType(CategoryPath("/FVS"), "FVSHeader", 0)
fvsHeaderType.add(StringDataType.dataType, 8, 'magic', "FVS magic")
fvsHeaderType.add(WordDataType.dataType, 'offsetFirstSector', "Relative offset to first sector header") # elems[3]
fvsHeaderType.add(WordDataType.dataType, 'version', "FVS version") # elems[0]
currentProgram.getDataTypeManager().addDataType(fvsHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Parse FVS header:
fvsHeader = createData(currentProgram, baseAddress, fvsHeaderType)
#variant = fvsHeader.getComponent(1).getValue()
version = fvsHeader.getComponent(2).getValue().getUnsignedValue()
print("FVS file version: {}".format(version))
if (version > 4):
    raise ValueError("Unsupported FVS file version")
createRefs(fvsHeader, fvsHeader.getComponent(2).getAddress())

# Data type for sector header
fvsSectorHeaderType = StructureDataType(CategoryPath("/FVS"), "FVSSectorHeader", 0)
fvsSectorHeaderType.add(ByteDataType.dataType, 'type', "FVS sector type")
if (version == 0):
    fvsSectorHeaderType.add(WordDataType.dataType, 'size', "FVS sector size")
else:
    fvsSectorHeaderType.add(DWordDataType.dataType, 'size', "FVS sector size")
currentProgram.getDataTypeManager().addDataType(fvsSectorHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Parse sector headers
refs = fvsHeader.getComponent(1).getReferencesFrom()
if (len(refs) >= 1):
    sectorHeaderAddress = refs[0].getToAddress()
    while True:
        try:
            sectorHeader = createData(currentProgram, sectorHeaderAddress, fvsSectorHeaderType)
        except CodeUnitInsertionException:
            break
        sectorType = sectorHeader.getComponent(0).getValue().getUnsignedValue()
        sectorLength = sectorHeader.getComponent(1).getValue().getUnsignedValue()
        print(f"Create FVS sector 0x{:02X} at {sectorHeaderAddress}")
        createFragment(currentProgram, "FVS sector 0x{:02X}".format(sectorType), sectorHeaderAddress, sectorLength + fvsSectorHeaderType.getLength())

        sectorAddress = sectorHeaderAddress.add(fvsSectorHeaderType.getLength())
        subSectorHeaderAddress = sectorAddress
        while (subSectorHeaderAddress < sectorAddress.add(sectorLength)):
            subSectorHeader = createData(currentProgram, subSectorHeaderAddress, fvsSectorHeaderType)
            subSectorType = subSectorHeader.getComponent(0).getValue().getUnsignedValue()
            subSectorLength = subSectorHeader.getComponent(1).getValue().getUnsignedValue()
            print(f"Create FVS subsector 0x{:02X} at {sectorHeaderAddress}")
            createFragment(currentProgram, "FVS sector 0x{:02X}".format(subSectorType), subSectorHeaderAddress, subSectorLength + fvsSectorHeaderType.getLength())
            subSectorHeaderAddress = subSectorHeaderAddress.add(fvsSectorHeaderType.getLength() + subSectorLength)

        sectorHeaderAddress = sectorHeaderAddress.add(fvsSectorHeaderType.getLength() + sectorLength)

if (version <= 1):
	# Data type for sector 0x20
	sector0x20Type = StructureDataType(CategoryPath("/FVS"), "Sector0x20", 0)
	sector0x20Type.add(WordDataType.dataType, 'producer', 'Producer id') # data + 0
	sector0x20Type.add(WordDataType.dataType, 'instrument', 'Instrument id') # data + 2
	sector0x20Type.add(WordDataType.dataType, 'source', 'Source id') # data + 4
	currentProgram.getDataTypeManager().addDataType(sector0x20Type, DataTypeConflictHandler.REPLACE_HANDLER)
else:
	# Data type for sector 0x20
	sector0x20Type = StructureDataType(CategoryPath("/FVS"), "Sector0x20", 0)
	sector0x20Type.add(WordDataType.dataType, 'producer', 'Producer id') # data + 0
	sector0x20Type.add(WordDataType.dataType, 'instrument', 'Instrument id') # data + 2
	sector0x20Type.add(WordDataType.dataType, 'source', 'source id') # data + 4
	sector0x20Type.add(Undefined8DataType.dataType, 'dateTime', 'Date and time') # data + 8
	currentProgram.getDataTypeManager().addDataType(sector0x20Type, DataTypeConflictHandler.REPLACE_HANDLER)

if (version == 0):
	# Data type for sector 0x50
	sector0x50Type = StructureDataType(CategoryPath("/FVS"), "Sector0x50", 0)
	sector0x50Type.add(WordDataType.dataType, 'word0', '?') # data + 0
	sector0x50Type.add(WordDataType.dataType, 'word1', '?') # data + 2
	sector0x50Type.add(WordDataType.dataType, 'word2', '?') # data + 4
	sector0x50Type.add(WordDataType.dataType, 'word3', '?') # data + 6
	sector0x50Type.add(DWordDataType.dataType, 'dword0', '?') # data + 8
	sector0x50Type.add(DWordDataType.dataType, 'dword1', '?') # data + 12
	sector0x50Type.add(DWordDataType.dataType, 'dword2', '?') # data + 16
	sector0x50Type.add(WordDataType.dataType, 'flags', 'Flags') # data + 20
	sector0x50Type.add(WordDataType.dataType, 'word5', '?') # data + 22
	sector0x50Type.add(StringDataType.dataType, 64, 'data', '?') # data + 24
	currentProgram.getDataTypeManager().addDataType(sector0x50Type, DataTypeConflictHandler.REPLACE_HANDLER)

	# Data type for sector 0x51
	sector0x51Type = StructureDataType(CategoryPath("/FVS"), "Sector0x51", 0)
	sector0x51Type.add(WordDataType.dataType, 'word0', '?') # data + 0
	sector0x51Type.add(WordDataType.dataType, 'word1', '?') # data + 2
	currentProgram.getDataTypeManager().addDataType(sector0x51Type, DataTypeConflictHandler.REPLACE_HANDLER)
elif (version == 1):
	# Data type for sector 0x52
	sector0x52Type = StructureDataType(CategoryPath("/FVS"), "Sector0x52", 0)
	sector0x52Type.add(WordDataType.dataType, 'word0', '?') # data + 0
	sector0x52Type.add(WordDataType.dataType, 'word1', '?') # data + 4
	sector0x52Type.add(WordDataType.dataType, 'word2', '?') # data + 8
	sector0x52Type.add(WordDataType.dataType, 'word3', '?') # data + 12
	sector0x52Type.add(WordDataType.dataType, 'flags', 'Flags') # data + 16
	sector0x52Type.add(WordDataType.dataType, 'word5', '?') # data + 20
	sector0x52Type.add(WordDataType.dataType, 'word6', '?') # data + 24
	sector0x52Type.add(DWordDataType.dataType, 'dword0', '?') # data + 36
	sector0x52Type.add(DWordDataType.dataType, 'dword1', '?') # data + 44
	sector0x52Type.add(DWordDataType.dataType, 'dword2', '?') # data + 48
	sector0x52Type.add(WordDataType.dataType, 'word7', '?') # data + 0x844
	sector0x52Type.add(StringDataType.dataType, 64, 'data', '?') # data + 0x846
	currentProgram.getDataTypeManager().addDataType(sector0x52Type, DataTypeConflictHandler.REPLACE_HANDLER)
elif (version == 2):
	# Data type for sector 0x52
	sector0x52Type = StructureDataType(CategoryPath("/FVS"), "Sector0x52", 0)
	sector0x52Type.add(WordDataType.dataType, 'word0', '?') # data + 0
	sector0x52Type.add(WordDataType.dataType, 'word1', '?') # data + 4
	sector0x52Type.add(WordDataType.dataType, 'word2', '?') # data + 8
	sector0x52Type.add(WordDataType.dataType, 'word3', '?') # data + 12
	sector0x52Type.add(WordDataType.dataType, 'flags', 'Flags') # data + 16
	sector0x52Type.add(WordDataType.dataType, 'word5', '?') # data + 20
	sector0x52Type.add(WordDataType.dataType, 'word6', '?') # data + 24
	sector0x52Type.add(DWordDataType.dataType, 'dword0', '?') # data + 36
	sector0x52Type.add(DWordDataType.dataType, 'dword1', '?') # data + 40
	sector0x52Type.add(DWordDataType.dataType, 'dword2', '?') # data + 44
	sector0x52Type.add(DWordDataType.dataType, 'dword3', '?') # data + 48
	sector0x52Type.add(DWordDataType.dataType, 'dword4', '?') # data + 52
	sector0x52Type.add(DWordDataType.dataType, 'dword5', '?') # data + 56
	sector0x52Type.add(DWordDataType.dataType, 'dword6', '?') # data + 60
	sector0x52Type.add(WordDataType.dataType, 'word7', '?') # data + 0x844
	sector0x52Type.add(StringDataType.dataType, 64, 'data', '?') # data + 0x846
	currentProgram.getDataTypeManager().addDataType(sector0x52Type, DataTypeConflictHandler.REPLACE_HANDLER)
elif (version == 3):
	# Data type for sector 0x52
	sector0x52Type = StructureDataType(CategoryPath("/FVS"), "Sector0x52", 0)
	sector0x52Type.add(DWordDataType.dataType, 'dword0', '?') # data + 0
	sector0x52Type.add(DWordDataType.dataType, 'dword1', '?') # data + 4
	sector0x52Type.add(DWordDataType.dataType, 'dword2', '?') # data + 8
	sector0x52Type.add(DWordDataType.dataType, 'dword3', '?') # data + 12
	sector0x52Type.add(WordDataType.dataType, 'flags', 'Flags') # data + 16
	sector0x52Type.add(DWordDataType.dataType, 'dword4', '?') # data + 20
	sector0x52Type.add(DWordDataType.dataType, 'dword5', '?') # data + 24
	sector0x52Type.add(DWordDataType.dataType, 'dword6', '?') # data + 28
	sector0x52Type.add(DWordDataType.dataType, 'dword7', '?') # data + 32
	sector0x52Type.add(DWordDataType.dataType, 'dword8', '?') # data + 36
	sector0x52Type.add(DWordDataType.dataType, 'dword9', '?') # data + 40
	sector0x52Type.add(DWordDataType.dataType, 'dword10', '?') # data + 44
	sector0x52Type.add(DWordDataType.dataType, 'dword11', '?') # data + 48
	sector0x52Type.add(DWordDataType.dataType, 'dword12', '?') # data + 52
	sector0x52Type.add(DWordDataType.dataType, 'dword13', '?') # data + 56
	sector0x52Type.add(DWordDataType.dataType, 'dword14', '?') # data + 60
	sector0x52Type.add(WordDataType.dataType, 'word1', '?') # data + 0x844
	sector0x52Type.add(StringDataType.dataType, 64, 'data', '?') # data + 0x846
	sector0x52Type.add(WordDataType.dataType, 'word2', '?') # data + 0x886
	sector0x52Type.add(WordDataType.dataType, 'word3', '?') # data + 0x888
	currentProgram.getDataTypeManager().addDataType(sector0x52Type, DataTypeConflictHandler.REPLACE_HANDLER)
elif (version == 4):
	# Data type for sector 0x52
	sector0x52Type = StructureDataType(CategoryPath("/FVS"), "Sector0x52", 0)
	sector0x52Type.add(DWordDataType.dataType, 'dword0', '?') # data + 0
	sector0x52Type.add(DWordDataType.dataType, 'dword1', '?') # data + 4
	sector0x52Type.add(DWordDataType.dataType, 'dword2', '?') # data + 8
	sector0x52Type.add(DWordDataType.dataType, 'dword3', '?') # data + 12
	sector0x52Type.add(WordDataType.dataType, 'flags', 'Flags') # data + 16
	sector0x52Type.add(DWordDataType.dataType, 'dword4', '?') # data + 20
	sector0x52Type.add(DWordDataType.dataType, 'dword5', '?') # data + 24
	sector0x52Type.add(DWordDataType.dataType, 'dword6', '?') # data + 28
	sector0x52Type.add(DWordDataType.dataType, 'dword7', '?') # data + 32
	sector0x52Type.add(DWordDataType.dataType, 'color0', '?') # data + 36
	sector0x52Type.add(DWordDataType.dataType, 'color1', '?') # data + 40
	sector0x52Type.add(DWordDataType.dataType, 'color2', '?') # data + 44
	sector0x52Type.add(DWordDataType.dataType, 'color3', '?') # data + 48
	sector0x52Type.add(DWordDataType.dataType, 'color4', '?') # data + 52
	sector0x52Type.add(DWordDataType.dataType, 'color5', '?') # data + 56
	sector0x52Type.add(DWordDataType.dataType, 'color6', '?') # data + 60
	sector0x52Type.add(WordDataType.dataType, 'word1', '?') # data + 64
	sector0x52Type.add(WordDataType.dataType, 'word2', '?') # data + 66
	sector0x52Type.add(ArrayDataType(ArrayDataType(DWordDataType.dataType, 256, 4), 2, 1024), 'array', '?') # data + 68
	sector0x52Type.add(WordDataType.dataType, 'word3', '?') # data + 0x844
	sector0x52Type.add(StringDataType.dataType, 64, 'caption', 'FvS caption') # data + 0x846
	sector0x52Type.add(WordDataType.dataType, 'word2', '?') # data + 0x886
	sector0x52Type.add(WordDataType.dataType, 'word3', '?') # data + 0x888
	currentProgram.getDataTypeManager().addDataType(sector0x52Type, DataTypeConflictHandler.REPLACE_HANDLER)

