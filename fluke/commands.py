try:
    from .fvf import FvfFile
    from .cur import CurFile
    from .fvs import FvsFile
    from .utils import DataTable, sciFormat, warning
except ImportError:
    from fvf import FvfFile
    from cur import CurFile
    from fvs import FvsFile
    from utils import DataTable, sciFormat, warning

import os
import tempfile
import subprocess
import textwrap


class Command:
    @classmethod
    def all(cls):
        for subClass in cls.__subclasses__():
            yield subClass

    @classmethod
    def flag(cls):
        name = cls.__name__.replace('Command', '')
        flag = ''
        for letter in name:
            if (len(flag) == 0):
                flag += letter.lower()
            elif letter.isupper():
                flag += '-'
                flag += letter.lower()
            else:
                flag += letter
        return flag

    @classmethod
    def help(cls):
        doc = ''
        if cls.__doc__ is not None:
            doc = textwrap.dedent(cls.__doc__)
        return doc.strip()

    @classmethod
    def appliesTo(cls, f):
        return type(f) in cls._appliesToTypes

    @classmethod
    def isTextCommand(cls):
        return cls._text


class FileVersionCommand(Command):
    "Print file version."

    _text = True
    _appliesToTypes = [FvfFile, CurFile]

    def __init__(self, f):
        print(f"  - version: {f.version}")


class FileVariantCommand(Command):
    """
        Print file variant.
        Applies only to CUR files.
    """

    _text = True
    _appliesToTypes = [CurFile]

    def __init__(self, f):
        print(f"  - variant: {f.variant}")


class SectorNumberCommand(Command):
    """
        Print number of sectors.
        Applies FVF and FVS files.
    """

    _text = True
    _appliesToTypes = [FvfFile, FvsFile]

    def __init__(self, f):
        print(f"  - number of sectors: {len(f)}")


class ListSectorsCommand(Command):
    """
        List sectors in file.
        Applies to FVF and FVS files.
    """

    _text = True
    _appliesToTypes = [FvfFile, FvsFile]

    def printList(self, f, indent=0):
        try:
            s = 0
            for sector in f:
                print(f"{' ' * indent}  - sector {s}: {sector!r}")
                self.printList(sector, indent + 4)
                s += 1
        except TypeError:
            pass

    def __init__(self, f):
        self.printList(f)


class CurveNumberCommand(Command):
    """
        Print number of curves in file.
        Applies only to CUR files.
    """

    _text = True
    _appliesToTypes = [CurFile]

    def __init__(self, f):
        print(f"  - number of curves: {len(f.curves)}")


class ListCurvesCommand(Command):
    """
        Print curve metadata.
        Applies only to CUR files.
    """

    _text = True
    _appliesToTypes = [CurFile]

    def __init__(self, f):
        c = 0
        for curve in f.curves:
            print(f"  - curve {c}: {curve}")
            c += 1


class CaptureNumberCommand(Command):
    """
        Print number of captures.
        Applies only to CUR files.
    """

    _text = True
    _appliesToTypes = [CurFile]

    @staticmethod
    def countCaptures(curve):
        n = 0
        while curve is not None:
            curve = curve.next
            n += 1
        return n

    def __init__(self, f, curves=None):
        c = 0
        for curve in f.curves:
            if (curves is None) or (c in curves):
                print(f"  - curve {c}: {CaptureNumberCommand.countCaptures(curve)}")
                c += 1


class ListCapturesCommand(Command):
    """
        Print captures metadata.
        Applies only to CUR files.
    """

    _text = True
    _appliesToTypes = [CurFile]

    def __init__(self, f, curves=None, captures=None):
        c = 0
        for curve in f.curves:
            if (curves is None) or (c in curves):
                capture = curve
                s = 0
                while capture is not None:
                    if (captures is None) or (s in captures):
                        print(f"  - curve {c} capture {s} ({capture.type}): \"{capture.description}\" at {capture.datetime}")  # noqa: E501
                        print(f"      * X-axis: Ts={sciFormat(capture.sampleTime)}{capture.xUnit} {sciFormat(capture.startTime)}{capture.xUnit}..{sciFormat(capture.endTime)}{capture.xUnit}")  # noqa: E501
                        print(f"      * Y-axis: {sciFormat(capture.gain)}{capture.yUnit} + {sciFormat(capture.offset)}{capture.yUnit}")  # noqa: E501
                    capture = capture.next
                    s += 1
                c += 1


class ExportCapturesCommand(Command):
    """
        Export capture to CSV file.
        Applies only to CUR files.
    """

    _text = False
    _appliesToTypes = [CurFile]

    def __init__(self, f, fileName=None, curves=None, captures=None):
        table = DataTable(f, curves, captures)

        csvFileName = os.path.splitext(fileName)[0] + '.csv'
        if os.path.exists(csvFileName):
            warning(f"Output file \"{csvFileName}\" already exists.")
            return

        with open(csvFileName, 'wt') as csvFile:
            table.writeHeaders(csvFile)
            table.writeData(csvFile)


class DisplayCapturesCommand(Command):
    """
        Display capture using GNU plot.
        Applies only to CUR files.
    """

    _text = False
    _appliesToTypes = [CurFile]

    def __init__(self, f, curves=None, captures=None):
        table = DataTable(f, curves, captures)

        with tempfile.NamedTemporaryFile('tw+') as gpFile, \
             tempfile.NamedTemporaryFile('tw+') as datFile:

            gpFile.write("set xdata time\n")
            gpFile.write("set timefmt \"%Y-%m-%dT%H:%M:%S\"\n")
            gpFile.write("set format x \"%H:%M:%S\"\n")
            for c in range(0, table.columns):
                if (c > 0):
                    gpFile.write("re")
                gpFile.write(f"plot '{datFile.name}' \
                               using 1:{c + 2} \
                               with lines \
                               title '{table.headers[c + 1]}'\n")

            table.writeData(datFile, delimiter=' ')

            datFile.flush()
            gpFile.flush()

            cmd = f"gnuplot -p {gpFile.name}"
            print(cmd)
            subprocess.run(cmd.split(' '))
