# CUR file parser
#@author    Pascal COMBES
#@category  Data
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.data import DataTypeConflictHandler, CategoryPath
from ghidra.program.model.data import ArrayDataType, StructureDataType
from ghidra.program.model.data import StringDataType, PascalStringDataType
from ghidra.program.model.data import ByteDataType, WordDataType, DWordDataType
from ghidra.program.model.data import FloatDataType, DoubleDataType
from ghidra.program.model.data import PointerDataType, StringDataType
from ghidra.program.model.symbol import RefType
from ghidra.program.model.util import CodeUnitInsertionException


def createData(prog, addr, dataType):
    try:
        return prog.getListing().createData(addr, dataType)
    except CodeUnitInsertionException:
        prog.getListing().clearCodeUnits(addr, addr.add(max(1, dataType.getLength() - 1)), True, monitor)
        return prog.getListing().createData(addr, dataType)


def createRefs(data, addr):
    for dataTypeComponent in data.getDataType().getComponents():
        if not dataTypeComponent.getFieldName().startswith('offset'):
            continue
        component = data.getComponent(dataTypeComponent.getOrdinal())
        offset = component.getValue().getUnsignedValue()
        if (offset != 0):
            component.addValueReference(addr.add(offset), RefType.DATA)


def saveData(data, fileName):
    with open(fileName, 'wt') as f:
        for c in range(0, data.getNumComponents()):
            d = data.getComponent(c).getValue().getSignedValue()
            f.write(str(d) + '\n')


def parseDataSet(ds, c, prog, addr, baseAddr):
    print("Found data set header at {}".format(addr))
    dataSetData = createData(prog, addr, dataSetHeaderType)
    createRefs(dataSetData, baseAddr)

    # Parse name
    refs = dataSetData.getComponent(1).getReferencesFrom()
    if (len(refs) >= 1):
        createData(prog, refs[0].getToAddress(), StringDataType.dataType)

    # Parse table 7
    refs = dataSetData.getComponent(4).getReferencesFrom()
    if (len(refs) >= 1):
        table7 = createData(prog, refs[0].getToAddress(), table7Type)
        createRefs(table7, baseAddr)

        # Parse table 8
        refs = table7.getComponent(3).getReferencesFrom()
        if (len(refs) >= 1):
            table8 = createData(prog, refs[0].getToAddress(), table8Type)
            createRefs(table8, baseAddr)

            # Parse table 9
            refs = table8.getComponent(0).getReferencesFrom()
            if (len(refs) >= 1):
                table9 = createData(prog, refs[0].getToAddress(), table9Type)
                createRefs(table9, baseAddr)

                # Parse table 10
                refs = table9.getComponent(2).getReferencesFrom()
                if (len(refs) >= 1):
                    table10 = createData(prog, refs[0].getToAddress(), table10Type)
                    createRefs(table10, baseAddr)

                    # Parse name
                    refs = table10.getComponent(1).getReferencesFrom()
                    if (len(refs) >= 1):
                        #sizeAddress = refs[0].getToAddress()
                        #sizeData = createData(prog, sizeAddress, WordDataType.dataType)

                        name = createData(prog, refs[0].getToAddress(), PascalStringDataType())
                        if (variant >= 8.0):
                            createData(prog, name.getMaxAddress().add(1), WordDataType.dataType) # param_4

    # Parse table 11
    numElems = None # TEST
    refs = dataSetData.getComponent(8).getReferencesFrom()
    if (len(refs) >= 1):
        table11Address = refs[0].getToAddress()
        sizeData = createData(prog, table11Address, WordDataType.dataType)
        size = sizeData.getValue().getUnsignedValue()

        for i in range(0, size):
            offsetData = createData(prog, table11Address.add(2 + 4 * i), DWordDataType.dataType)
            offset = offsetData.getValue().getUnsignedValue()
            if (offset != 0):
                offsetData.addValueReference(baseAddr.add(offset), RefType.DATA)

            # Parse data header (table 12)
            refs = offsetData.getReferencesFrom()
            if (len(refs) >= 1):
                dataHeaderData = createData(prog, refs[0].getToAddress(), dataHeaderType)
                createRefs(dataHeaderData, baseAddr)

                if numElems is None:  # TEST
                    numElems = dataHeaderData.getComponent(0).getValue().getUnsignedValue()

                refs = dataHeaderData.getComponent(1).getReferencesFrom()
                if (len(refs) >= 1):
                    dataAddress = refs[0].getToAddress()
                    print("Found data at {}".format(dataAddress))

                    createData(prog, dataAddress, WordDataType.dataType)
                    sizeData = createData(prog, dataAddress.add(2), WordDataType.dataType)
                    size = sizeData.getValue().getUnsignedValue()
                    if (size == 1):
                        data = createData(prog, dataAddress.add(4), ArrayDataType(ByteDataType.dataType, numElems, size))
                    if (size == 4):
                        data = createData(prog, dataAddress.add(4), ArrayDataType(DWordDataType.dataType, numElems, size))
                    saveData(data, "curve_{}_{}_{}.csv".format(c, ds, i))

                refs = dataHeaderData.getComponent(8).getReferencesFrom()
                if (len(refs) >= 1):
                    print("Unparsed table 13 at {}".format(refs[0].getToAddress()))

    refs = dataSetData.getComponent(dataSetData.getNumComponents() - 1).getReferencesFrom()
    if (len(refs) >= 1):
        parseDataSet(ds + 1, c, prog, refs[0].getToAddress(), baseAddr)


# Search for the CUR file header:
if currentAddress is not None:
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'CUR_', None, True, monitor)
else:
    baseAddress = currentProgram.getMemory().findBytes(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0), 'CUR_', None, True, monitor)
if (baseAddress is None) and (currentAddress is not None):
    baseAddress = currentProgram.getMemory().findBytes(currentAddress, 'CUR_', None, False, monitor)
if (baseAddress is None):
    raise RuntimeError("Could not find CUR header")
print("Found CUR header at {}".format(baseAddress))

# Data type for CUR file header:
curHeaderType = StructureDataType(CategoryPath("/CUR"), "CURHeader", 0)
curHeaderType.add(StringDataType.dataType, 4, 'magic', "CUR magic")
curHeaderType.add(DoubleDataType.dataType, 'variant', "CUR variant")
curHeaderType.add(DoubleDataType.dataType, 'version', "CUR version")
curHeaderType.add(DWordDataType.dataType, 'offsetCurves', "Offset to curves")
curHeaderType.add(DWordDataType.dataType, 'unused1', "Unused") # TODO
curHeaderType.add(DWordDataType.dataType, 'unused2', "Unused")
curHeaderType.add(DWordDataType.dataType, 'offset5', "Offset to table 5")
curHeaderType.add(DWordDataType.dataType, 'offset1', "Offset to table 1")
curHeaderType.add(DWordDataType.dataType, 'offset2', "Offset to table 2")
currentProgram.getDataTypeManager().addDataType(curHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Parse CUR header:
curHeader = createData(currentProgram, baseAddress, curHeaderType)
variant = curHeader.getComponent(1).getValue()
print("CUR file variant: {}".format(variant))
if (variant < 0.0):
    raise ValueError("Unsupported CUR file variant")
version = curHeader.getComponent(2).getValue()
print("CUR file version: {}".format(version))
if (version > 9.0):
    raise ValueError("Unsupported CUR file version")
createRefs(curHeader, baseAddress)

# Data type for curves header:
curveHeaderType = StructureDataType(CategoryPath("/CUR"), "CurveHeader", 0)
curveHeaderType.add(StringDataType.dataType, 12, 'name', "Curve Name")
curveHeaderType.add(WordDataType.dataType, 'index', "Curve index")
curveHeaderType.add(DWordDataType.dataType, 'offset', "Offset to first data")
currentProgram.getDataTypeManager().addDataType(curveHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for data set header:
dataSetHeaderType = StructureDataType(CategoryPath("/CUR"), "DataSetHeader", 0)
dataSetHeaderType.add(DWordDataType.dataType, 'type', "Data type") # 1 <- [1, 2, 8], 2 <- [4, 6, 12]
dataSetHeaderType.add(DWordDataType.dataType, 'offsetName', "Offset to data name")
dataSetHeaderType.add(StringDataType.dataType, 14, 'datetime', "Date and time")
dataSetHeaderType.add(DWordDataType.dataType, 'unused1', "Unused")
dataSetHeaderType.add(DWordDataType.dataType, 'offset7', "Offset to table 7")
dataSetHeaderType.add(WordDataType.dataType, 'unused2', "Unused")
dataSetHeaderType.add(WordDataType.dataType, 'flags', "Data flags")
dataSetHeaderType.add(DoubleDataType.dataType, 'double1', "?")
dataSetHeaderType.add(DWordDataType.dataType, 'offsetData', "Offset to data header")
if (variant >= 9.0):
    dataSetHeaderType.add(DWordDataType.dataType, 'dword1', "?")
    dataSetHeaderType.add(WordDataType.dataType, 'word1', "?")
if (variant >= 10.0):
    dataSetHeaderType.add(WordDataType.dataType, 'word2', "?")
dataSetHeaderType.add(DWordDataType.dataType, 'offsetNext', "Offset to next header")
currentProgram.getDataTypeManager().addDataType(dataSetHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for data header:
dataHeaderType = StructureDataType(CategoryPath("/CUR"), "DataHeader", 0)
dataHeaderType.add(DWordDataType.dataType, 'size', "Size of data")
dataHeaderType.add(DWordDataType.dataType, 'offset', "Offset to data")
dataHeaderType.add(StringDataType.dataType, 12, 'unit', "Data unit") 
dataHeaderType.add(WordDataType.dataType, 'unitIndex', "Index in the unit table")
dataHeaderType.add(WordDataType.dataType, 'word2', "?")
dataHeaderType.add(DoubleDataType.dataType, 'scaleGain', "Gain to apply to data")
dataHeaderType.add(DoubleDataType.dataType, 'scaleOffset', "Offset to apply to data")
dataHeaderType.add(DoubleDataType.dataType, 'double1', "?")
dataHeaderType.add(DWordDataType.dataType, 'offset13', "Offset to table 13")
if (variant > 1.0):
    dataHeaderType.add(DWordDataType.dataType, 'dword1', "?") # else 0x0000
if (variant > 3.0):
    dataHeaderType.add(WordDataType.dataType, 'word3', "?") # else 0x7FFF
if (variant > 6.0):
    dataHeaderType.add(WordDataType.dataType, 'word4', "?")
    dataHeaderType.add(WordDataType.dataType, 'word5', "?")
if (variant > 9.0):
    dataHeaderType.add(DoubleDataType.dataType, 'windowMin', "Min value in window")
    dataHeaderType.add(DoubleDataType.dataType, 'windowMaw', "Max value in window")
    dataHeaderType.add(WordDataType.dataType, 'type', "Type of data")
currentProgram.getDataTypeManager().addDataType(dataHeaderType, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 1 item:
table1Type = StructureDataType(CategoryPath("/CUR"), "Table1", 0)
table1Type.add(WordDataType.dataType, 'index', "Index")
table1Type.add(DWordDataType.dataType, 'offset3', "Offset to table3")
currentProgram.getDataTypeManager().addDataType(table1Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 2 item:
table2Type = StructureDataType(CategoryPath("/CUR"), "Table2", 0)
table2Type.add(StringDataType.dataType, 8, 'unused', "Unused")
table2Type.add(DWordDataType.dataType, 'offset18', "Offset to table 18")
table2Type.add(WordDataType.dataType, 'index1', "Index in table1")
table2Type.add(WordDataType.dataType, 'index', "Index")
currentProgram.getDataTypeManager().addDataType(table2Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 3:
table3Type = StructureDataType(CategoryPath("/CUR"), "Table3", 0)
table3Type.add(ByteDataType.dataType, 'flags', "Flags")
table3Type.add(DWordDataType.dataType, 'offset15', "Offset to table 15")
table3Type.add(WordDataType.dataType, 'word1', "?")
table3Type.add(WordDataType.dataType, 'word2', "?")
table3Type.add(DWordDataType.dataType, 'offset16', "Offset to table 16")
if (variant > 2.0):
    table3Type.add(DWordDataType.dataType, 'offsetString', "Offset to byte-length prefixedString")
if (variant > 4.0):
    table3Type.add(DWordDataType.dataType, 'offsetWinPos', "Offset to window position")
if (variant > 5.0):
    table3Type.add(WordDataType.dataType, 'word3', "?")
if (variant > 8.0):
    table3Type.add(WordDataType.dataType, 'word4', "?")
currentProgram.getDataTypeManager().addDataType(table3Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for window position:
winPosType = StructureDataType(CategoryPath("/CUR"), "WinPos", 0)
if (variant < 9.0):
    winPosType.add(WordDataType.dataType, 'word1', "?") # data[0]
    winPosType.add(WordDataType.dataType, 'word2', "?") # data[1]
    winPosType.add(WordDataType.dataType, 'word3', "?") # data[2]
    winPosType.add(WordDataType.dataType, 'word4', "?") # data[3]
    winPosType.add(WordDataType.dataType, 'word5', "?") # data[4]
    winPosType.add(WordDataType.dataType, 'word6', "?") # data[5]
else:
    winPosType.add(DWordDataType.dataType, 'word1', "?") # data[0]
    winPosType.add(DWordDataType.dataType, 'word2', "?") # data[1]
    winPosType.add(DWordDataType.dataType, 'word3', "?") # data[2]
    winPosType.add(DWordDataType.dataType, 'word4', "?") # data[3]
    winPosType.add(DWordDataType.dataType, 'word5', "?") # data[4]
    winPosType.add(DWordDataType.dataType, 'word6', "?") # data[5]
    winPosType.add(DWordDataType.dataType, 'word7', "?") # data[6]
    winPosType.add(DWordDataType.dataType, 'word8', "?") # data[8]
winPosType.add(WordDataType.dataType, 'word0', "?") # param_4
currentProgram.getDataTypeManager().addDataType(winPosType, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 5:
table5Type = StructureDataType(CategoryPath("/CUR"), "Table5", 0)
table5Type.add(ByteDataType.dataType, 'isData', "Whether there is data")
table5Type.add(DWordDataType.dataType, 'offset6', "Offset to table6")
currentProgram.getDataTypeManager().addDataType(table5Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 7:
table7Type = StructureDataType(CategoryPath("/CUR"), "Table7", 0)
table7Type.add(WordDataType.dataType, 'word1', "?")
table7Type.add(DWordDataType.dataType, 'dword1', "?")
table7Type.add(DWordDataType.dataType, 'dword2', "?")
table7Type.add(DWordDataType.dataType, 'offset8', "Offset to table8")
table7Type.add(DWordDataType.dataType, 'dword3', "?")
currentProgram.getDataTypeManager().addDataType(table7Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 8:
table8Type = StructureDataType(CategoryPath("/CUR"), "Table8", 0)
table8Type.add(DWordDataType.dataType, 'offset9', "Offset to table9")
table8Type.add(DWordDataType.dataType, 'dword1', "?")
currentProgram.getDataTypeManager().addDataType(table8Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 9:
table9Type = StructureDataType(CategoryPath("/CUR"), "Table9", 0)
table9Type.add(WordDataType.dataType, 'word1', "?") # Should be 1
table9Type.add(StringDataType.dataType, 16, 'creator', "Creator name") # Should be FlukeView
table9Type.add(DWordDataType.dataType, 'offset10', "Offset to table10")
currentProgram.getDataTypeManager().addDataType(table9Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 10:
table10Type = StructureDataType(CategoryPath("/CUR"), "Table10", 0)
table10Type.add(WordDataType.dataType, 'word1', "?")
table10Type.add(DWordDataType.dataType, 'offset', "Offset to word length-prefixed string")
currentProgram.getDataTypeManager().addDataType(table10Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 13:
table13Type = StructureDataType(CategoryPath("/CUR"), "Table13", 0)
table13Type.add(WordDataType.dataType, 'type', "Type of data")
table13Type.add(DoubleDataType.dataType, 'double1', "?")
table13Type.add(DoubleDataType.dataType, 'double1', "?")
table13Type.add(DWordDataType.dataType, 'offset14', "Offset to table 14")
currentProgram.getDataTypeManager().addDataType(table13Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 14:
table14Type = StructureDataType(CategoryPath("/CUR"), "Table14", 0)
table14Type.add(WordDataType.dataType, 'word1', "?")
table14Type.add(WordDataType.dataType, 'word2', "?")
table14Type.add(WordDataType.dataType, 'word3', "?")
table14Type.add(WordDataType.dataType, 'word4', "?")
currentProgram.getDataTypeManager().addDataType(table14Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 15:
table15Type = StructureDataType(CategoryPath("/CUR"), "Table15", 0)
table15Type.add(WordDataType.dataType, 'word1', "?")
table15Type.add(WordDataType.dataType, 'word2', "?")
table15Type.add(WordDataType.dataType, 'word3', "?")
currentProgram.getDataTypeManager().addDataType(table15Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 16:
#table16Type = StructureDataType(CategoryPath("/CUR"), "Table16", 0)
#table16Type.add(WordDataType.dataType, 'word', "Table length")
#table16Type.add(DWordDataType.dataType, 'offset16', "Offset to table 16")
#table16Type.add(DWordDataType.dataType, 'offset17', "Offset to table 17")
#currentProgram.getDataTypeManager().addDataType(table16Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 17:
table17Type = StructureDataType(CategoryPath("/CUR"), "Table17", 0)
table17Type.add(DWordDataType.dataType, 'dword1', "?")
table17Type.add(WordDataType.dataType, 'word1', "?")
table17Type.add(WordDataType.dataType, 'word2', "?")
table17Type.add(ByteDataType.dataType, 'byte1', "?")
currentProgram.getDataTypeManager().addDataType(table17Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 18:
table18Type = StructureDataType(CategoryPath("/CUR"), "Table18", 0)
table18Type.add(WordDataType.dataType, 'word', "Table length")
table18Type.add(DWordDataType.dataType, 'offset19', "Offset to table 19")
table18Type.add(DWordDataType.dataType, 'offset22', "Offset to table 22")
currentProgram.getDataTypeManager().addDataType(table18Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 19:
table19Type = StructureDataType(CategoryPath("/CUR"), "Table19", 0)
table19Type.add(WordDataType.dataType, 'word1', "?")
table19Type.add(DoubleDataType.dataType, 'double1', "?")
table19Type.add(DoubleDataType.dataType, 'double2', "?")
table19Type.add(DWordDataType.dataType, 'dword', "?")
table19Type.add(WordDataType.dataType, 'word2', "?")
table19Type.add(WordDataType.dataType, 'word3', "?")
table19Type.add(DoubleDataType.dataType, 'double3', "?")
table19Type.add(DoubleDataType.dataType, 'double4', "?")
table19Type.add(ByteDataType.dataType, 'byte1', "?")
table19Type.add(ByteDataType.dataType, 'byte2', "?")
if ((2.0 < variant) and (variant < 9.0)):
    table19Type.add(DoubleDataType.dataType, 'double5', "?")
    table19Type.add(DoubleDataType.dataType, 'double6', "?")
if (variant > 3.0):
    table19Type.add(DWordDataType.dataType, 'offset20', "Offset to table 20")
currentProgram.getDataTypeManager().addDataType(table19Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 21:
table21Type = StructureDataType(CategoryPath("/CUR"), "Table21", 0)
table21Type.add(DWordDataType.dataType, 'dword1', "?")
if (variant <= 5.0):
    table21Type.add(DWordDataType.dataType, 'dword2', "?")
else:
    table21Type.add(DoubleDataType.dataType, 'double', "?")
table21Type.add(DWordDataType.dataType, 'dword3', "?")
currentProgram.getDataTypeManager().addDataType(table21Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Data type for table 22:
table22Type = StructureDataType(CategoryPath("/CUR"), "Table22", 0)
table22Type.add(WordDataType.dataType, 'word1', "?")
table22Type.add(DoubleDataType.dataType, 'double1', "?")
table22Type.add(DoubleDataType.dataType, 'double2', "?")
table22Type.add(DWordDataType.dataType, 'offset', "Offset to word")
table22Type.add(WordDataType.dataType, 'word2', "?")
table22Type.add(WordDataType.dataType, 'word3', "?")
table22Type.add(DoubleDataType.dataType, 'double3', "?")
table22Type.add(DoubleDataType.dataType, 'double4', "?")
table22Type.add(ByteDataType.dataType, 'byte1', "?")
table22Type.add(ByteDataType.dataType, 'byte2', "?")
if ((2.0 < variant) and (variant < 9.0)):
    table22Type.add(DoubleDataType.dataType, 'double5', "?")
    table22Type.add(DoubleDataType.dataType, 'double6', "?")
currentProgram.getDataTypeManager().addDataType(table22Type, DataTypeConflictHandler.REPLACE_HANDLER)

# Parse curve headers: 
refs = curHeader.getComponent(3).getReferencesFrom()
if (len(refs) >= 1):
    curveNumberAddress = refs[0].getToAddress()
    curveNumberData = createData(currentProgram, curveNumberAddress, WordDataType.dataType)
    curveNumber = curveNumberData.getValue().getUnsignedValue()
    for c in range(0, curveNumber):
        curveHeader = createData(currentProgram, curveNumberAddress.add(2 + c * curveHeaderType.getLength()), curveHeaderType)
        createRefs(curveHeader, baseAddress)

        refs = curveHeader.getComponent(2).getReferencesFrom()
        if (len(refs) >= 1):
            parseDataSet(0, c, currentProgram, refs[0].getToAddress(), baseAddress)

# Parse table 5:
refs = curHeader.getComponent(6).getReferencesFrom()
if (len(refs) >= 1):
    table5 = createData(currentProgram, refs[0].getToAddress(), table5Type)
    createRefs(table5, baseAddress)

    # Parse table6:
    refs = table5.getComponent(1).getReferencesFrom()
    if (len(refs) >= 1):
        table6Address = refs[0].getToAddress()
        sizeData = createData(currentProgram, table6Address, WordDataType.dataType)
        size = sizeData.getValue().getUnsignedValue()

        for i in range(0, size):
            table6 = createData(currentProgram, table6Address.add(2 + 12 * i), ArrayDataType(FloatDataType.dataType, 3, 4))

# Parse table 1:
refs = curHeader.getComponent(7).getReferencesFrom()
if (len(refs) >= 1):
    table1Address = refs[0].getToAddress()
    sizeData = createData(currentProgram, table1Address, WordDataType.dataType)
    size = sizeData.getValue().getUnsignedValue()
    for i in range(0, size):
        table1 = createData(currentProgram, table1Address.add(2 + i * table1Type.getLength()), table1Type)
        createRefs(table1, baseAddress)

        # Parse table 3:
        refs = table1.getComponent(1).getReferencesFrom()
        if (len(refs) >= 1):
            table3 = createData(currentProgram, refs[0].getToAddress(), table3Type)
            createRefs(table3, baseAddress)

            # Parse table 15:
            refs = table3.getComponent(1).getReferencesFrom()
            if (len(refs) >= 1):
                table15 = createData(currentProgram, refs[0].getToAddress(), table15Type)

            # Parse table 16:
            refs = table3.getComponent(4).getReferencesFrom()
            if (len(refs) >= 1):
                table16Address = refs[0].getToAddress()
                sizeData = createData(currentProgram, table16Address, WordDataType.dataType)
                size = sizeData.getValue().getUnsignedValue()
                for i in range(0, size):
                    offsetData = createData(currentProgram, table16Address.add(2 + 4*i), DWordDataType.dataType)
                    offset = offsetData.getValue().getUnsignedValue()
                    if (offset != 0):
                        offsetData.addValueReference(baseAddress.add(offset), RefType.DATA)

                        # Parse table 17
                        refs = offsetData.getReferencesFrom()
                        if (len(refs) >= 1):
                            table17 = createData(currentProgram, refs[0].getToAddress(), table17Type)

            # Parse string
            if (variant > 2.0):
                refs = table3.getComponent(5).getReferencesFrom()
                if (len(refs) >= 1):
                    createData(currentProgram, refs[0].getToAddress(), PascalStringDataType.dataType)

            # Parse window position
            if (variant > 4.0):
                refs = table3.getComponent(6).getReferencesFrom()
                if (len(refs) >= 1):
                    winPos = createData(currentProgram, refs[0].getToAddress(), winPosType)
   
# Parse table 2:
refs = curHeader.getComponent(8).getReferencesFrom()
if (len(refs) >= 1):
    table2Address = refs[0].getToAddress()
    sizeData = createData(currentProgram, table2Address, WordDataType.dataType)
    size = sizeData.getValue().getUnsignedValue()
    for i in range(0, size):
        table2 = createData(currentProgram, table2Address.add(2 + i * table2Type.getLength()), table2Type)
        createRefs(table2, baseAddress)
        
        # Parse table 18
        refs = table2.getComponent(1).getReferencesFrom()
        if (len(refs) >= 1):
            table18 = createData(currentProgram, refs[0].getToAddress(), table18Type)
            createRefs(table18, baseAddress)

            # Parse table 19
            refs = table18.getComponent(1).getReferencesFrom()
            if (len(refs) >= 1):
                table19 = createData(currentProgram, refs[0].getToAddress(), table19Type)
                createRefs(table19, baseAddress)

                # Parse table 20
                if (variant > 3.0):
                    refs = table19.getComponent(table19.getNumComponents() - 1).getReferencesFrom()
                    if (len(refs) >= 1):
                        table20Address = refs[0].getToAddress()
                        sizeData = createData(currentProgram, table20Address, WordDataType.dataType)
                        size = sizeData.getValue().getUnsignedValue()
                        for i in range(0, size):
                            offsetData = createData(currentProgram, table20Address.add(2 + 4*i), DWordDataType.dataType)
                            offset = offsetData.getValue().getUnsignedValue()
                            if (offset != 0):
                                offsetData.addValueReference(baseAddress.add(offset), RefType.DATA)

                                # Parse table 21
                                refs = offsetData.getReferencesFrom()
                                if (len(refs) >= 1):
                                    table21 = createData(currentProgram, refs[0].getToAddress(), table21Type)

            # Parse table 22
            refs = table18.getComponent(2).getReferencesFrom()
            if (len(refs) >= 1):
                table22 = createData(currentProgram, refs[0].getToAddress(), table22Type)
                createRefs(table22, baseAddress)

                refs = table22.getComponent(3).getReferencesFrom()
                if (len(refs) >= 1):
                    word = createData(currentProgram, refs[0].getToAddress(), WordDataType.dataType)
