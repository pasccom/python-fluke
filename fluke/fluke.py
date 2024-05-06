try:
    from .utils import printStruct, debug, info, warning
except ImportError:
    from utils import printStruct, debug, info, warning

import os
import struct

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
            debug(f'subclass.magic: {subClass.MAGIC}')
            if (len(subClass.MAGIC) - len(magic) > 0):
                magic += f.read(len(subClass.MAGIC) - len(magic))
            debug(f'MAGIC: {magic}')
            if (magic[:len(subClass.MAGIC)] == subClass.MAGIC):
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
