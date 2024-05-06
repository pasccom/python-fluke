try:
    from .fluke import FlukeFile, FlukeSector
    from .utils import printStruct, debug, info, warning
except ImportError:
    from fluke import FlukeFile, FlukeSector
    from utils import printStruct, debug, info, warning

import struct


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

