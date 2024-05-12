try:
    from .fluke import FlukeFile, FlukeSector
    from .utils import printStruct, debug, info, warning
except ImportError:
    from fluke import FlukeFile, FlukeSector
    from utils import printStruct, debug, info, warning

import struct


class MetaFvsSector(type):
    """
    Metaclass implementing the magic allowing to create a FVS sector with the right type.
    The magic is based on the sector type (written in the binary data).
    """
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
    """
    This class represents a FVS file sector.

    :param f: Underlying file object.
    :param begin: Begining of the sector.
    :param sizeType: The Type for the size (``'L'`` represents 4-byte size).

    .. note::
       The sector type is automatically determined from the binary data,
       the instance will have the type corresponding to the sector in the file.
    """

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
        """
        FVS sector size (in bytes).
        """
        return self.__size


class FvsSector0x10(FvsSector):
    """
    This class represents a FVS file sector divided into subsectors.

    The instances of this class are iterable, each item representing the subsectors,
    which are instances of subclasses of :py:class:`FvsSector`

    :param f: Underlying file object.
    :param begin: Begining of the sector.
    :param sizeType: The Type for the size (``'L'`` represents 4-byte size).


    """

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
    """
    This class represents an empty FVS file sector inserted at the end of FVS files.


    :param f: Underlying file object.
    :param begin: Begining of the sector.
    :param sizeType: The Type for the size (``'L'`` represents 4-byte size).
    """
    TYPE = 0x70

    def __init__(self, f, begin, sizeType='L'):
        pass


class UnknownFvsSector(FvsSector):
    """
    This class represents an unknown FVS file sector.

    .. note::
       Most of the data sectors will have this type, as FVS data sector format has not been retro-engineered (yet).

    :param f: Underlying file object.
    :param begin: Begining of the sector.
    :param sizeType: The Type for the size (``'L'`` represents 4-byte size).
    """
    def __init__(self, f, begin, type, sizeType='L'):
        super().__init__(f, begin, sizeType)
        self.__type = type


    def __repr__(self):
        return super().__repr__().replace('(', f'(0x{self.__type:02X}, ')


    @property
    def type(self):
        """
        FVS sector type.
        """
        return self.__type


class FvsFile(FlukeFile):
    """
    This class represents a *Fluke* FVS file.

    :py:class:`FvsFile` instances are iterable. This allows to access the various sectors in the FVS file.
    The sectors can be any class inheriting :py:class:`FvsSector`.

    :param path: The path to the *Fluke* file
    :param f: An optional file object

    .. note::
        If the file object is not present the file corresponding to path will be opened
        and data will be read from it. Otherwise, data is read from the file object.
        The file object argument is mainly for internal purposes.

    .. note::
        Thanks to the magic mechanism, this class is most simply constructed using::


           with FlukeFile('/path/to/fluke_file.fvs') as ff:
               print(f"{ff}: {ff.version}")
    """

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
        """
        FVS file version

        .. note::
            Currently, only FVS files with version below 4 (included) are supported.
        """
        if self.__version is None:
            self.__readHeader()
        return self.__version

