import sys
import datetime

from progress.bar import Bar
from warnings import warn as warning


def debug(msg):
    pass
    #print(f"DEBUG: {msg}", file=sys.stderr, flush=True)


def info(msg):
    print(f"INFO:  {msg}", file=sys.stderr, flush=True)


def printStruct(fmt, data):
    d = 0
    f = 0
    n = 0
    dataStr = ['??']*len(data)
    while (f < len(fmt)) and (d < len(data)):
        if (fmt[f] == '<'):
            f = f + 1
            continue
        elif (fmt[f].isdigit()):
            n = 10*n + int(fmt[f])
            f = f + 1
            continue

        if (fmt[f] == 's') or (n == 0):
            n = 1

        for i in range(0, n):
            if (fmt[f] == 's'):
                dataStr[d] = str(data[d])
            elif (fmt[f] == 'b'):
                dataStr[d] = str(data[d])
            elif (fmt[f] == 'h'):
                dataStr[d] = str(data[d])
            elif (fmt[f] == 'l'):
                dataStr[d] = str(data[d])
            elif (fmt[f] == 'B'):
                dataStr[d] = f'0x{data[d]:02X}'
            elif (fmt[f] == 'H'):
                dataStr[d] = f'0x{data[d]:04X}'
            elif (fmt[f] == 'L'):
                dataStr[d] = f'0x{data[d]:08X}'
            elif (fmt[f] == 'f'):
                dataStr[d] = str(data[d])
            elif (fmt[f] == 'd'):
                dataStr[d] = str(data[d])
            else:
                warning(f"Unknown data format: {fmt[f]}")
            d = d + 1

        n = 0
        f = f + 1

    return '(' + ', '.join(dataStr) + ')'


def num2str(x):
    if x is None:
        return ''
    if type(x) is datetime.datetime:
        return x.isoformat()

    s = f"{x:.6f}"

    if '.' in s:
        while (s[-1] == '0'):
            s = s[:-1]
        if (s[-1] == '.'):
            s = s[:-1]

    return s


def sciFormat(x):
    prefixes = 'qryzafpnµm kMGTPEZYRQ'

    if (x == 0.):
        return '0'

    for i in range(0, len(prefixes)):
        if (abs(x) < 1000 ** (i + 1 - 10)):
            return f"{num2str(x / (1000 ** (i - 10)))}{prefixes[i]}".strip()

    return f"{num2str(x / (1000 ** 10))}Q"


class DataTable:
    def __init__(self, f, curves=None, captures=None):
        self.__file = f
        self.__curves = curves

        self.__headers = []
        self.__lines = 0
        self.__captures = []
        captureStartTimes = []
        captureSampleTimes = []

        c = 0
        for curve in f.curves:
            if (self.__curves is None) or (c in self.__curves):
                capture = curve
                s = 0
                while capture is not None:
                    captureOk = False
                    if (captures is None) or (s in captures):
                        captureOk = True
                        # Start time
                        if (len(captureStartTimes) <= s):
                            captureStartTimes += [capture.startTime]
                        elif (captureStartTimes[s] != capture.startTime):
                            warning(f"Inconsistent start time for curve {c}[{s}]. Skipping capture.")
                            captureOk = False
                        # Sample time
                        if (len(captureSampleTimes) <= s):
                            captureSampleTimes += [capture.sampleTime]
                        elif (captureSampleTimes[s] != capture.sampleTime):
                            warning(f"Inconsistent sample time for curve {c}[{s}]. Skipping capture.")
                            captureOk = False
                        # X data
                        if (len(self.__headers) <= 0):
                            self.__headers += [capture.xLabel]
                        elif (self.__headers[0] != capture.xLabel):
                            warning(f"Inconsistent X data for curve {c}[{s}]. Skipping capture.")
                            captureOk = False
                        # Y data
                        if (len(self.__headers) <= c + 1):
                            self.__headers += [capture.yLabel]
                        elif (self.__headers[c + 1] != capture.yLabel):
                            debug(f"\"{self.__headers[c + 1]}\" != \"{capture.yLabel}\"")
                            warning(f"Inconsistent Y data for curve {c}[{s}]. Skipping capture.")
                            captureOk = False
                    if captureOk:
                        self.__captures += [s]
                        self.__lines += len(capture)
                    capture = capture.next
                    s += 1
                c += 1


        self.__lines = self.lines // c
        self.__columns = c


    @property
    def lines(self):
        return self.__lines


    @property
    def columns(self):
        return self.__columns


    @property
    def headers(self):
        return self.__headers


    def dataLine(self, captures):
        for c in captures:
            if c is not None:
                x = c.xData
                break
        else:
            return

        for i in range(0, len(x)):
            line = [x[i]]
            for c in captures:
                if c is not None:
                    #line += [c.yData[i]]
                    line += [c.yDataFluke[i]]
                else:
                    line += None
            yield line


    @property
    def data(self):
        c = 0
        captures = []

        for curve in self.__file.curves:
            if (self.__curves is None) or (c in self.__curves):
                captures += [curve]
            c += 1


        s = 0
        while any([c is not None for c in captures]):
            if (self.__captures is None) or (s in self.__captures):
                for line in self.dataLine(captures):
                    yield line
            captures = [(c.next if c is not None else None) for c in captures]
            s += 1


    def writeHeaders(self, f, delimiter=','):
        f.write(','.join(self.__headers) + '\n')


    def writeData(self, f, delimiter=','):
        l = 0
        prog = Bar(f"Writing {f.name}", fill='=', max=self.__lines, width=80, bar_prefix=' [', bar_suffix='] ')
        for line in self.data:
            f.write(delimiter.join([num2str(l) for l in line]) + '\n')
            l += 1
            prog.suffix = f'{l} / {self.__lines} lines'
            prog.goto(l)
        print()


