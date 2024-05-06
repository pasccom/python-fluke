try:
    from .fluke import FlukeFile, FvfFile, CurFile, FvsFile
    from .commands import Command
    from .utils import debug, info, warning
except ImportError:
    from fluke import FlukeFile, FvfFile, CurFile, FvsFile
    from commands import Command
    from utils import debug, info, warning

import argparse
import textwrap


def applyCommands(commands, flukeFile, cmdArgs):
    debug(f"applyCommands({commands}, {flukeFile})")
    if any([cmd.isTextCommand() for cmd in commands]):
        print(f"{flukeFile}:")
    for cmd in Command.all():
        if (cmd in commands) and cmd.appliesTo(flukeFile):
            args = [flukeFile]
            for argName in cmd.__init__.__code__.co_varnames[2:cmd.__init__.__code__.co_argcount]:
                if (argName == 'fileName'):
                    args += [str(flukeFile).split(':')[0]]
                else:
                    args += [getattr(cmdArgs, argName)]
            cmd(*args)


def main():
    argParser = argparse.ArgumentParser(
        prog="fvfReader",
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent("""\
            Read data in Fluke Viewer Files (*.fvf, *.cur, *.fvs) files.

            The data organization has been obtained by retro-engineering
            the official libraries.
        """)
    )

    argParser.add_argument(
        '-v', '--version',
        action='version',
        version=textwrap.dedent("""
        fvfReader version:     0.1
        Supports:
            - FVF file version:  2
            - CUR file version:  9.0
            - CUR file variant:  10.0
        """)
    )
    argParser.add_argument(
        '-s', '--sectors',
        nargs='*',
        action='store',
        dest='sectors',
        type=int,
        help="Select specific sectors of a FVF file"
    )
    argParser.add_argument(
        '-c', '--curves',
        nargs='*',
        action='store',
        dest='curves',
        type=int,
        help="Select specific curves of a CUR file"
    )
    argParser.add_argument(
        '-n', '--captures',
        nargs='*',
        action='store',
        dest='captures',
        type=int,
        help="Select specific captures in a CUR file"
    )

    argParser.add_argument(
        '--cur',
        action='store_const',
        dest='sector_type',
        const=CurFile,
        help=textwrap.dedent("""
            Select sectors containing CUR files in a FVF file.
            This option is not taken into account if sector is specified.
            Only the last type specified (using --cur or --fvs) is taken into account.
        """)
    )
    argParser.add_argument(
        '--fvs',
        action='store_const',
        dest='sector_type',
        const=FvsFile,
        help=textwrap.dedent("""
            Select sectors containing FVS files in a FVF file.
            This option is not taken into account if sector is specified.
            Only the last type specified (using --cur or --fvs) is taken into account.
        """)
    )

    for cmd in Command.all():
        argParser.add_argument(
            '--' + cmd.flag(),
            action='append_const',
            dest='commands',
            const=cmd,
            help=cmd.help()
        )

    argParser.add_argument(
        'filePath',
        nargs='+',
        action='store',
        help="Path to a Fluke viewer file to be processed"
    )

    args = argParser.parse_args()
    print(args)

    for filePath in args.filePath:
        with FlukeFile(filePath) as flukeFile:
            if (type(flukeFile) is FvfFile) and hasattr(args, 'sectors') and (args.sectors is not None):
                for s in args.sectors:
                    applyCommands(args.commands, flukeFile[s], args)
            elif (type(flukeFile) is FvfFile) and hasattr(args, 'sector_type') and (args.sector_type is not None):
                for sector in flukeFile:
                    if type(sector) is args.sector_type:
                        applyCommands(args.commands, sector, args)
            else:
                applyCommands(args.commands, flukeFile, args)
                if type(flukeFile) is FvfFile:
                    for sector in flukeFile:
                        applyCommands(args.commands, sector, args)


main()
