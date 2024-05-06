try:
    from .fluke import FlukeFile, FlukeSector
    from .utils import printStruct, debug, info, warning
except ImportError:
    from fluke import FlukeFile, FlukeSector
    from utils import printStruct, debug, info, warning

import struct


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
        if self.__sectors is not None:
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
