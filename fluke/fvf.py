try:
    from .fluke import FlukeFile, FlukeSector
    from .utils import printStruct, debug, info, warning
except ImportError:
    from fluke import FlukeFile, FlukeSector
    from utils import printStruct, debug, info, warning

import struct


class FvfSector(FlukeSector):
    """
    FVF file sector abstraction.

    :param f: The underlying file (it should be a FvfFile).
    :param begin: The sector beginning.
    :param size: The sector size.
    :param index: The sector index in the FVF file
    """


    def __init__(self, f, begin, size, index):
        super().__init__(f, begin)
        self.size = size  #: The sector size.
        self.index = index  #: The sector index


class FvfFile(FlukeFile):
    """
    This class represents a *Fluke* FVF file.

    :py:class:`FvfFile` instances are iterable. This allows to access the various sectors in the FVF file.
    The sectors can be any class inheriting :py:class:`FlukeFile`.

    :param path: The path to the *Fluke* file
    :param f: An optional file object

    .. note::
        If the file object is not present the file corresponding to path will be opened
        and data will be read from it. Otherwise, data is read from the file object.
        The file object argument is mainly for internal purposes.

    .. note::
        Thanks to the magic mechanism, this class is most simply constructed using::


           with FlukeFile('/path/to/fluke_file.fvf') as ff:
               print(f"{ff}: {ff.version}")
    """


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
        """
        Close the *Fluke* file, if the file is opened.

        .. note::
            This method should not be used, rely the context manager instead.
        """
        if self.__sectors is not None:
            for sector in self.__sectors:
                if sector is not None:
                    sector.close()

        super().close()


    def __readHeader(self):
        fmt = '<HLLLHL'
        # data[0] version
        # data[1]
        # data[2]
        # data[3]
        # data[4] sector number
        # data[5]

        if self.seek(8) is None:
            raise RuntimeError(f"File is not open")

        data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
        self.__version = data[0]
        self.__sectors = [None] * data[4]

        if (self.__version >= 2):
            warning(f"Unsupported FVF file version: {self.__version}")

    def __readSector(self, sector):
        fmt = '<LLHHHH'

        # data[0] sector begin offset
        # data[1] sector size
        # data[2] sector index
        # data[3]
        # data[4]
        # data[5]

        if self.seek(28 + 16*sector) is None:
            raise RuntimeError(f"File is not open")
        if (sector >= len(self.__sectors)):
            raise ValueError(f"Sector index too large: {sector}")

        data = struct.unpack(fmt, self.read(struct.calcsize(fmt)))

        self.__sectors[sector] = FlukeFile(f'{self.filePath}:{sector}', FvfSector(self, *data[0:3]))


    @property
    def version(self):
        """
        FVF file version

        .. note::
            Currently, only first version FVF files are supported.
        """
        if self.__version is None:
            self.__readHeader()
        return self.__version
