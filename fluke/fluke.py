try:
    from .utils import printStruct, debug, info, warning
except ImportError:
    from utils import printStruct, debug, info, warning

import os
import struct
import datetime

from enum import Enum


class MetaFlukeFile(type):
    def __call__(cls, *args):
        if hasattr(cls, 'MAGIC'):
            return super().__call__(*args)

        if (len(args) >= 2) and (args[1] is not None):
            return MetaFlukeFile.__createFlukeFile(cls, args[1], *args)
        elif (len(args) >= 1):
            with open(args[0], 'rb') as f:
                return MetaFlukeFile.__createFlukeFile(cls, f, *args)

        return super().__call__(*args)


    @staticmethod
    def __createFlukeFile(cls, f, *args):
        f.seek(0)
        magic = b''
        for subClass in cls.__subclasses__():
            magic += f.read(len(subClass.MAGIC) - len(magic))
            debug(f'MAGIC: {magic}')
            if (magic == subClass.MAGIC):
                f.seek(0)
                return subClass(*args)


class FlukeFile(metaclass=MetaFlukeFile):
    def __init__(self, path, f=None):
        self.filePath = path
        self.__file = f

        if self.__file is not None:
            self.__file.seek(0)
            self.validate()


    def __str__(self):
        return f"{self.filePath}"


    def __repr__(self):
        return f"{self.__class__.__name__}({self.filePath})"


    def __enter__(self):
        self.open()
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


    def validate(self):
        if hasattr(self.__class__, 'MAGIC'):
            magic = self.__file.read(len(self.__class__.MAGIC))
            if (magic == self.__class__.MAGIC):
                info(f"Validated magic for {self.__class__.__name__}")
            else:
                raise ValueError(f"Invalid magic: {magic}")


    def open(self):
        if self.__file is None:
            self.__file = open(self.filePath, 'rb')
            debug(f"Opened {self.filePath}")
        else:
            self.__file.seek(0)

        self.validate()


    def seek(self, pos, origin=os.SEEK_SET):
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.seek(pos, origin)


    def tell(self):
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.tell()


    def read(self, size=-1):
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.read(size)


    def close(self):
        if self.__file is not None:
            self.__file.close()
            debug(f"Closed {self.filePath}")
            self.__file = None


    def readWordPrefixedString(self, offset):
        fmt = '<H'

        if self.__file is None:
            warning("This file is closed")
            return

        self.__file.seek(offset)
        l = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        if (l[0] == 0):
            return ''
        return self.__file.read(l[0]).decode()


class FlukeSector:
    def __init__(self, f, begin):
        self.begin = begin

        self.__file = f
        self.__pos = 0


    def __repr__(self):
        return f"{self.__class__.__name__}(0x{self.begin:08x}, 0x{self.size:08x})"


    def seek(self, pos, origin=os.SEEK_SET):
        if (origin == os.SEEK_SET):
            self.__pos = pos
        elif (origin == os.SEEK_POS):
            self.__pos += pos
        elif (origin == os.SEEK_END):
            self.__pos = self.size + pos
        else:
            raise ValueError(f"Invalid seek origin: {origin}")
        return self.__pos


    def tell(self):
        return self.__pos


    def read(self, size=-1):
        size = min(size, self.size - self.__pos)
        #print(f"{self.__class__.__name__} 0x{self.size:02X} 0x{self.__pos:02X} 0x{size:02X}")
        if (size == 0):
            return b''
        return self._read(size)


    def _read(self, size=-1):
        if self.__file is None:
            warning("This sector belongs to a closed file")
            return

        self.__file.seek(self.begin + self.__pos, os.SEEK_SET)
        r = self.__file.read(size)
        self.__pos += len(r)
        return r


    def close(self):
        self.__file = None


class CurCurve:
    MAGIC = b'FlukeView'

    __units = ['', 's', 'Hz', 'V', 'dBm', 'dBV', 'dBW', 'D%+', 'D%-', 'RPM', 'A', '°', '°C', '°F', 'Vs', 'VV', 'Ohm', 'As', 'AA', 'W', 'WW', '%', 'cycles', 'events', 'dB', 'J', 'K', 'Pa', 'm', 'F', 'VAR', 'VA', '%r', '%f', 'PF']

    def __init__(self, f, name, identifier, offset):
        if (offset <= 0):
            raise ValueError(f"Invalid offset: {offset}")

        self.__file = f
        if type(name) is bytes:
            self.name = name.strip().replace(b'\0', b'').decode()
        else:
            self.name = name.strip().replace('\0', '')
        self.identifier = identifier
        self.__offset = offset

        self.__type = None
        self.__descOffset = None
        self.__desc = None
        self.__datetime = None

        self.__next = None

        self.__offset7 = None # TODO rename
        self.__offsetData = None

        self.__xUnit = None
        self.__yUnit = None

        self.__size = None
        self.__sampleTime = None
        self.__timeOffset = None
        self.__dataGain = None
        self.__dataOffset = None
        self.__rawData = None


    def __str__(self):
        return f"{self.name} ({self.identifier})"


    def __repr__(self):
        return f"CurCurve(\"{self.name}\", {self.identifier}, 0x{self.__offset:08x})"


    def __readHeader(self):
        fmt = '<LL2s2s2s4s2s2sLLHHdLL'
        if (self.__file.variant >= 9.0):
            fmt += 'H'
        if (self.__file.variant >= 10.0):
            fmt += 'H'
        if (self.__file.variant >= 9.0):
            fmt += 'L'
        # data[0] Curve type
        # data[1] Offset to description
        # data[2] Hour
        # data[3] Minute
        # data[4] Seconds
        # data[5] Year
        # data[6] Month
        # data[7] Day
        # data[8]
        # data[9] Offset to table 7
        # data[10]
        # data[11] Flags
        # data[12]
        # data[13] Offset to table 11
        # data[14]
        # data[15]
        # data[16]
        # data[-1] Offset to next header

        if self.__file.seek(self.__offset) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        self.__type = data[0]
        self.__descOffset = data[1] if (data[1] > 0) else None
        self.__datetime = datetime.datetime(int(data[5]), int(data[6]), int(data[7]), int(data[2]), int(data[3]), int(data[4]))
        debug(f'CurveHeader: {printStruct(fmt, data)}')

        self.__offset7 = data[9]
        self.__offsetData = data[13]
        if (data[-1] > 0):
            self.__next = CurCurve(self.__file, self.name, self.identifier, data[-1])

        #self.__readTable7() # TEST


    def __readTable7(self): # TODO rename
        if self.__offset7 is None:
            self.__readHeader()
        if self.__offset7 is None:
            return

        fmt = '<HLLLL' # TODO Table 7
        # data[0] is ignored (always 0)
        # data[1] is ignored (always 0)
        # data[2] is ignored (always 0)
        # data[3] is offset to table 8
        # data[4] is ignored (always 0)

        if self.__file.seek(self.__offset7) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        debug(f'Table 7: {printStruct(fmt, data)}')

        fmt = '<LL' # TODO Table 8
        # data[0] is offset to table 9
        # data(1] is ignored (always 0)

        if self.__file.seek(data[3]) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        debug(f'Table 8: {printStruct(fmt, data)}')

        fmt = '<H16sL' # TODO Table 9
        # data[0] must equal to 1
        # data[1] must equal to FlukeView (padded to 16 bytes with null characters)
        # data[2] is offset to tabme 10

        if self.__file.seek(data[0]) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        debug(f'Table 9: {printStruct(fmt, data)}')

        if (data[0] != 1):
            return

        magic = bytes([c for c in data[1] if c != 0])
        if (magic != self.__class__.MAGIC):
            warning(f'Invalid table 9 at 0x{self.__file.tell() - struct.calcsize(fmt):08x}')
            return

        fmt = '<HL' # TODO Table 10
        # data[0] is ignored (always 17)
        # data[1] points to a name

        if self.__file.seek(data[2]) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        debug(f'Table 10: {printStruct(fmt, data)}')
        debug(f'Name: {self.__file.readWordPrefixedString(data[1])}')


    def __readData(self):
        if self.__offsetData is None:
            self.__readHeader()
        if self.__offsetData is None:
            return

        fmt = '<H'
        # data[0] table size

        if self.__file.seek(self.__offsetData) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))

        fmt = f'<{data[0]}L'
        # data[i] offset to axis data

        dataOffsets = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        debug(f'Data offsets: {printStruct(fmt, dataOffsets)}')

        for p in range(0, 2):
            for o in dataOffsets:
                fmt = '<LL12sHHdddL'
                if (self.__file.variant > 1.0):
                    fmt += 'L'
                if (self.__file.variant > 3.0):
                    fmt += 'h'
                if (self.__file.variant > 6.0):
                    fmt += 'HH'
                if (self.__file.variant > 9.0):
                    fmt += 'ddH'

                # data[0] data size
                # data[1] data offset
                # data[2] unitStr
                # data[3] unitIndex
                # data[4]
                # data[5] Gain to be applied to data
                # data[6] Offset to be applied to data
                # data[7] (for data always equal to gain, for time always equal to 1)
                # data[8] offset to table 13
                # data[9]
                # data[10]
                # data[11]
                # data[12]
                # data[13] Min value in window
                # data[14] Max value in window
                # data[15] Data type

                if self.__file.seek(o) is None:
                    raise RuntimeError(f"File is not open")

                data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
                debug(f'Data header: {printStruct(fmt, data)}')

                if (data[1] == 0) and (self.__size is None):
                    self.__xUnit = data[3]
                    self.__size = data[0]
                    self.__sampleTime = data[5]
                    self.__timeOffset = data[6]
                    break
                elif (data[1] != 0) and (self.__size is not None):
                    if self.__rawData is None:
                        self.__yUnit = data[3]
                        self.__rawData = []
                        self.__dataGain = data[5]
                        self.__dataOffset = data[6]
                    self.__rawData += [self.__readVector(data[1], self.__size)]


    def __readVector(self, offset, size):
        fmt = '<HH'
        # data[0]
        # data[1] byte size

        if self.__file.seek(offset) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))

        if (data[1] == 1):
            fmt = f'<{size}b'
        else:
            fmt = f'<{size}l'

        data =  struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        return data


    def __len__(self):
        return self.__size


    @property
    def sampleTime(self):
        if self.__sampleTime is None:
            self.__readData()
        return self.__sampleTime


    @property
    def startTime(self):
        if self.__timeOffset is None:
            self.__readData()
        return self.__timeOffset

    @property
    def endTime(self):
        if (self.__size is None) or (self.__sampleTime is None) or (self.__timeOffset is None):
            self.__readData()
        return self.__timeOffset + self.__sampleTime * self.__size


    @property
    def gain(self):
        if self.__dataGain is None:
            self.__readData()
        return self.__dataGain


    @property
    def offset(self):
        if self.__dataOffset is None:
            self.__readData()
        return self.__dataOffset


    @property
    def xData(self):
        if (self.__size is None) or (self.__sampleTime is None) or (self.__timeOffset is None):
            self.__readData()
        return [self.__datetime + datetime.timedelta(seconds=self.__sampleTime*i + self.__timeOffset) for i in range(0, self.__size)]


    @property
    def yDataRaw(self):
        if self.__rawData is None:
            self.__readData()
        return self.__rawData


    @property
    def yData(self):
        if self.__rawData is None:
            self.__readData()
        if (len(self.__rawData) == 1):
            return [self.__dataGain*d + self.__dataOffset for d in self.__rawData[0]]
        elif (len(self.__rawData) == 2):
            return [self.__dataGain*sum(d)/len(d) + self.__dataOffset for d in zip(*self.__rawData)]
        else:
            raise NotImplementedError(f"Files with {len(self.__rawData)} data vectors are not currently supported")


    @property
    def yDataFluke(self):
        if self.__rawData is None:
            self.__readData()
        if (len(self.__rawData) == 1):
            return [self.__dataGain*d + self.__dataOffset for d in self.__rawData[0]]
        elif (len(self.__rawData) == 2):
            return [self.__dataGain*int(sum(d)/len(d)) + self.__dataOffset for d in zip(*self.__rawData)]
        else:
            raise NotImplementedError(f"Files with {len(self.__rawData)} data vectors are not currently supported")


    @property
    def xUnit(self):
        if self.__xUnit is None:
            self.__readData()
        if self.__xUnit is not None:
            return CurCurve.__units[self.__xUnit]
        return ''


    @property
    def yUnit(self):
        if self.__yUnit is None:
            self.__readData()
        if self.__yUnit is not None:
            return CurCurve.__units[self.__yUnit]
        return ''


    @property
    def xLabel(self):
        return f"X ({self.xUnit})"


    @property
    def yLabel(self):
        return f"{self.name} ({self.yUnit})"


    @property
    def type(self):
        if self.__type is None:
            self.__readHeader()
        return self.__type # TEST
        types = [0, 1, 1, None, 2, None, 2, None, 1, None, None, None, 2]
        if (self.__type < len(types)):
            return types[self.__type]


    @property
    def description(self):
        if self.__descOffset is None:
            self.__readHeader()
        if self.__desc is None:
            self.__desc = self.__file.readWordPrefixedString(self.__descOffset)
        return self.__desc


    @property
    def datetime(self):
        if self.__datetime is None:
            self.__readHeader()
        return self.__datetime


    @property
    def next(self):
        if self.__next is None:
            self.__readHeader()
        return self.__next


class CurCurves:
    def __init__(self, f, offset, mapping=None):
        if (offset <= 0):
            raise ValueError(f"Invalid offset: {offset}")

        self.__file = f
        self.__offset = offset
        self.__mapping = mapping
        self.__curves = None


    def __len__(self):
        if self.__mapping is not None:
            return len(self.__mapping)
        if self.__curves is None:
            self.__readNumber()
        return len(self.__curves)


    def __getitem__(self, curve):
        if self.__curves is None:
            self.__readNumber()

        if self.__mapping is not None:
            if (curve >= len(self.__mapping)):
                raise ValueError(f"Curve index too large: {curve}")
            curve = self.__mapping[curve]['curveIndex'] - 1

        if (curve >= len(self.__curves)):
            raise ValueError(f"Curve index too large: {curve}")

        if self.__curves[curve] is None:
            self.__readCurve(curve)
        return self.__curves[curve]


    def __iter__(self):
        if self.__curves is None:
            self.__readNumber()

        if self.__mapping is not None:
            N = len(self.__mapping)
        else:
            N = len(self.__curves)

        for c in range(0, N):
            if self.__mapping is not None:
                curve = self.__mapping[c]['curveIndex'] - 1
            else:
                curve = c
            if self.__curves[curve] is None:
                self.__readCurve(curve)
            yield self.__curves[curve]


    def __readNumber(self):
        fmt = '<H'
        # Number of curves

        if self.__file.seek(self.__offset) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        self.__curves = [None] * data[0]


    def __readCurve(self, c):
        fmt = '<12sHL'
        # data[0] Curve name
        # data[1] Curve id
        # data[2] Curve offset

        if self.__file.seek(self.__offset + 2 + struct.calcsize(fmt) * c) is None:
            raise RuntimeError(f"File is not open")

        self.__curves[c] = CurCurve(self.__file, *struct.unpack(fmt, self.__file.read(struct.calcsize(fmt))))


class CurFile(FlukeFile):
    MAGIC = b'CUR_'

    def __init__(self, path, f=None):
        super().__init__(path, f)

        self.__variant = None
        self.__version = None

        self.__curvesOffset = None
        self.__curves = None

        self.__mappingOffset = None
        self.__mapping = None

    def __readHeader(self):
        fmt = '<ddLLLLLL'
        # data[0] Variant (<= 10.0)
        # data[1] Version (<= 9.0)
        # data[2] Offset to curves
        # data[3]
        # data[4]
        # data[5] Offset to table 5
        # data[6] Offset to window table
        # data[7] Offset to mapping table

        if self.seek(4) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))

        debug(f"Variant:             {data[0]}")
        debug(f"Version:             {data[1]}")
        debug(f"Curve number offset: 0x{data[2]:08X}")
        debug(f"Table 5 offset:      0x{data[5]:08X}")
        debug(f"Table 1 offset:      0x{data[6]:08X}")
        debug(f"Table 2 offset:      0x{data[7]:08X}")

        self.__variant = data[0]
        self.__version = data[1]
        self.__curvesOffset = data[2] if (data[2] > 0) else None
        self.__offset5 = data[5] if (data[5] > 0) else None
        self.__offset1 = data[6] if (data[6] > 0) else None
        self.__mappingOffset = data[7] if (data[7] > 0) else None

        if (self.__variant < 0.0):
            warning(f"Invalid variant: {self.__variant}")
        if (self.__version > 9.0):
            warning(f"Unsupported CUR file version: {self.__version}")


    def __readMapping(self):
        if self.__mappingOffset is None:
            self.__readHeader()
        if self.__mappingOffset is None:
            return

        fmt = '<H'
        # Number of items

        if self.seek(self.__mappingOffset) is None:
            raise RuntimeError(f"File is not open")

        (mappingLen, ) = struct.unpack(fmt, self.read(struct.calcsize(fmt)))

        self.__mapping = []
        for i in range(0, mappingLen):
            fmt = '<8sLHH'
            # data[0] unused
            # data[1] Offset to cursor information
            # data[2] Window index
            # data[3] Curve index

            self.seek(self.__mappingOffset + 2 + 16*i)
            data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
            self.__mapping += [{
                'cursorOffset': data[1],
                'windowIndex': data[2],
                'curveIndex': data[3],
            }]


    @property
    def version(self):
        if self.__version is None:
            self.__readHeader()
        return self.__version


    @property
    def variant(self):
        if self.__variant is None:
            self.__readHeader()
        return self.__variant


    @property
    def curves(self):
        if self.__curves is None:
            if self.__curvesOffset is None:
                self.__readHeader()
            if self.__curvesOffset is None:
                return None
            if self.__mapping is None:
                self.__readMapping()

            self.__curves = CurCurves(self, self.__curvesOffset, self.__mapping)
        return self.__curves


class MetaFvsSector(type):
     def __call__(cls, f, begin, *args, **kwArgs):
        if hasattr(cls, 'TYPE') or (len(cls.__subclasses__()) == 0):
            return super().__call__(f, begin, *args, **kwArgs)

        if f.seek(begin) is None:
            raise RuntimeError(f"File is not open")

        fmt = f'<B'
        data = f.read(struct.calcsize(fmt))
        if (len(data) == 0):
            return
        (t, ) = struct.unpack(fmt, data)
        debug(f"FvsSector tyep: 0x{t:02X}")

        for subClass in cls.__subclasses__():
            if (hasattr(subClass, 'TYPE') and (t == subClass.TYPE)):
                return subClass(f, begin, *args, **kwArgs)

        return UnknownFvsSector(f, begin, t, *args, **kwArgs)


class FvsSector(FlukeSector, metaclass=MetaFvsSector):
    def __init__(self, f, begin, sizeType='L'):
        super().__init__(f, begin)


        if self.seek(1) is None:
            raise RuntimeError(f"File is not open")

        self.__size = 1
        fmt = f'<{sizeType}'
        data = struct.unpack(fmt, self._read(struct.calcsize(fmt)))
        self.__size += struct.calcsize(fmt) + data[0]


    def __repr__(self):
        return f"{self.__class__.__name__}(0x{self.begin:02X}, 0x{self.__size:02X})"


    @property
    def size(self):
        return self.__size


class FvsSector0x10(FvsSector):
    TYPE = 0x10

    def __init__(self, f, begin, sizeType='L'):
        super().__init__(f, begin, sizeType)

        self.__sizeType = sizeType
        self.__sectors = []


    def __iter__(self):
        currentSector = None
        for sector in self.__sectors:
            if sector is None:
                return
            currentSector = sector
            yield currentSector

        if currentSector is None:
            currentSector = FvsSector(self, 5, self.__sizeType)
            self.__sectors += [currentSector]
            if currentSector is None:
                return
            yield currentSector

        while True:
            currentSector = FvsSector(self, currentSector.begin + currentSector.size, self.__sizeType)
            self.__sectors += [currentSector]
            if currentSector is None:
                break
            yield currentSector


class FvsSector0x70(FvsSector):
    TYPE = 0x70

    def __init__(self, f, begin, sizeType='L'):
        pass


class UnknownFvsSector(FvsSector):
    def __init__(self, f, begin, type, sizeType='L'):
        super().__init__(f, begin, sizeType)
        self.__type = type


    def __repr__(self):
        return super().__repr__().replace('(', f'(0x{self.__type:02X}, ')


    @property
    def type(self):
        return self.__type


class FvsFile(FlukeFile):
    MAGIC = b'FV.FVS\x1a\x00'

    def __init__(self, path, f=None):
        super().__init__(path, f)

        self.__version = None
        self.__sectors = []


    def __readHeader(self):
        fmt = '<HH'

        if self.seek(8) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
        self.__version = data[1]
        if (self.__version == 0):
            self.__sectors = [FvsSector(self, data[0] + 10, 'H')]
        else:
            self.__sectors = [FvsSector(self, data[0] + 10, 'L')]


        if (self.__version > 4):
            warning(f"Unsupported FVS file version: {self.__version}")


    def __iter__(self):
        if (len(self.__sectors) == 0):
            self.__readHeader()

        for sector in self.__sectors:
            currentSector = sector
            if type(currentSector) is not FvsSector0x70:
                yield currentSector

        while type(currentSector) is not FvsSector0x70:
            if (self.__version == 0):
                currentSector = FvsSector(self, currentSector.begin + currentSector.size, 'H')
            else:
                currentSector = FvsSector(self, currentSector.begin + currentSector.size, 'L')
            self.__sectors += [currentSector]
            if type(currentSector) is not FvsSector0x70:
                yield currentSector


    @property
    def version(self):
        if self.__version is None:
            self.__readHeader()
        return self.__version


class FvfSector(FlukeSector):
    def __init__(self, f, begin, size, index, *args):
        super().__init__(f, begin)
        self.size = size
        self.index = index


class FvfFile(FlukeFile):
    MAGIC = b'FV.FVF\x1a\x00'


    def __init__(self, path, f=None):
        super().__init__(path, f)

        self.__version = None
        self.__sectors = None


    def __repr__(self):
        if self.__version is not None:
            return f"FvfFile({self.filePath}, {self.__version})"
        else:
            return f"FvfFile({self.filePath})"


    def __len__(self):
        if self.__sectors is None:
            self.__readHeader()
        return len(self.__sectors)


    def __getitem__(self, sector):
        if self.__sectors is None:
            self.__readHeader()
        if (sector >= len(self.__sectors)):
            raise ValueError(f"Sector index too large: {sector}")
        if self.__sectors[sector] is None:
            self.__readSector(sector)
        return self.__sectors[sector]


    def __iter__(self):
        if self.__sectors is None:
            self.__readHeader()
        for s in range(0, len(self.__sectors)):
            if self.__sectors[s] is None:
                self.__readSector(s)
            yield self.__sectors[s]


    def close(self):
        for sector in self.__sectors:
            if sector is not None:
                sector.close()

        super().close()


    def __readHeader(self):
        fmt = '<HLLLHL'

        if self.seek(8) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
        self.__version = data[0]
        self.__sectors = [None] * data[4]

        if (self.__version >= 2):
            warning(f"Unsupported FVF file version: {self.__version}")

    def __readSector(self, sector):
        fmt = '<LLHHHH'

        if self.seek(28 + 16*sector) is None:
            raise RuntimeError(f"File is not open")
        if (sector >= len(self.__sectors)):
            raise ValueError(f"Sector index too large: {sector}")

        self.__sectors[sector] = FlukeFile(f'{self.filePath}:{sector}', FvfSector(self, *struct.unpack(fmt, self.read(struct.calcsize(fmt)))))


    @property
    def version(self):
        if self.__version is None:
            self.__readHeader()
        return self.__version

