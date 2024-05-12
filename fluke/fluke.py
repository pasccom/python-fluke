try:
    from .utils import debug, info, warning
except ImportError:
    from utils import debug, info, warning

import os
import struct


class MetaFlukeFile(type):
    """
    Metaclass implementing the magic allowing to create a *Fluke* file with the right type.
    The magic is based on the magic header included in *Fluke* files.
    """
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
    """
    This is the main class of *Fluke* file API.

    It creates a Fluke file abstraction whose actual type depends on the given file type,
    relying on the information given inside the file (magic header), not the extension.

    :param path: The path to the *Fluke* file
    :param f: An optional file object

    .. note::
        If the file object is not present the file corresponding to path will be opened
        and data will be read from it. Otherwise, data is read from the file object.
        The file object argument is mainly for internal purposes.

    The class implements the context manager interface and should be used as follows::

        with FlukeFile('/path/to/fluke_file.fvf') as ff:
            print(f"{ff}: {ff.version}")
    """

    def __init__(self, path, f=None):
        self.filePath = path  #: The path to the *Fluke* file.
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
        """
        Validate the *Fluke* file by checking the magic header corresponds.

        :raise ValueError: If this is not the case.
        """
        if hasattr(self.__class__, 'MAGIC'):
            magic = self.__file.read(len(self.__class__.MAGIC))
            if (magic == self.__class__.MAGIC):
                info(f"Validated magic for {self.__class__.__name__}")
            else:
                raise ValueError(f"Invalid magic: {magic}")

    def open(self):
        """
        Open the *Fluke* file or reset the file pointer (if the file is already opened)

        .. note::
            This method should not be used, rely the context manager instead.
        """
        if self.__file is None:
            self.__file = open(self.filePath, 'rb')
            debug(f"Opened {self.filePath}")
        else:
            self.__file.seek(0)

        self.validate()

    def seek(self, pos, origin=os.SEEK_SET):
        """
        Modify the position of the file pointer.

        :param pos: The offset to be applied to the file pointer.
        :param orgin: The origin of the displacement:

          - ``os.SEEK_SET`` The offset is relative to the origin
          - ``os.SEEK_CURRENT`` The offset is relative to the current file pointer position
          - ``os.SEEK_END`` The offset is relative to the end .`
        """
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.seek(pos, origin)

    def tell(self):
        """
        Get the position of the file pointer.

        :return: The file pointer position
        """
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.tell()

    def read(self, size=-1):
        """
        Read data from the file (starting at file pointer position).

        :param size: The number of bytes to read.
        :return: The bytes read from the file.
        """
        if self.__file is None:
            warning("This file is closed")
            return

        return self.__file.read(size)

    def close(self):
        """
        Close the *Fluke* file, if the file is opened.

        .. note::
            This method should not be used, rely the context manager instead.
        """
        if self.__file is not None:
            self.__file.close()
            debug(f"Closed {self.filePath}")
            self.__file = None

    def readWordPrefixedString(self, offset):
        """
        Read a string prefixed by its length as two bytes at the given offset

        :param offset: The position (relative to the file begining where to read data).
        :return: The read string as a *Python* string.
        """
        fmt = '<H'

        if self.__file is None:
            warning("This file is closed")
            return

        self.__file.seek(offset)
        length = struct.unpack(fmt, self.__file.read(struct.calcsize(fmt)))
        if (length[0] == 0):
            return ''
        return self.__file.read(length[0]).decode()


class FlukeSector:
    """
    FVF and FVS files are divided into sectors. This class implements the basic functionnality
    to parse these sectors as standard Python files.

    :param f: The underlying file (it can be a :py:class:`FlukeFile` or
       another :py:class:`FlukeSector`).
    :param begin: The sector beginning.
    """

    def __init__(self, f, begin):
        self.begin = begin  #: The offset to the sector beginning.

        self.__file = f
        self.__pos = 0

    def __repr__(self):
        return f"{self.__class__.__name__}(0x{self.begin:08x}, 0x{self.size:08x})"

    def seek(self, pos, origin=os.SEEK_SET):
        """
        Modify the position of the file pointer.

        :param pos: The offset to be applied to the file pointer.
        :param orgin: The origin of the displacement:

          - ``os.SEEK_SET`` The offset is relative to the origin
          - ``os.SEEK_CURRENT`` The offset is relative to the current file pointer position
          - ``os.SEEK_END`` The offset is relative to the end.
        """
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
        """
        Get the position of the file pointer.

        :return: The file pointer position
        """
        return self.__pos

    def read(self, size=-1):
        """
        Read data from the file (starting at file pointer position).

        .. note::
            The number of bytes to be read is automatically limited to the number of bytes
            available in the sector (consequently, this method cannot return data outside the
            sector.

        :param size: The number of bytes to read.
        :return: The bytes read from the file.
        """
        size = min(size, self.size - self.__pos)
        if (size == 0):
            return b''
        return self._read(size)

    def _read(self, size=-1):
        """
        Read data from the file (starting at file pointer position).

        .. note::
            This method allows to read data from the sector without being limited.
            It should be used only by this class and derived classes.

        :param size: The number of bytes to read.
        :return: The bytes read from the file.
        """
        if self.__file is None:
            warning("This sector belongs to a closed file")
            return

        self.__file.seek(self.begin + self.__pos, os.SEEK_SET)
        r = self.__file.read(size)
        self.__pos += len(r)
        return r

    def close(self):
        """
        Emulate file closing.
        """
        self.__file = None
