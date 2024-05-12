REPOSITORY DESCRIPTION
----------------------
This repository contains a Python parser for Fluke binary files.

Fluke binary files contain measurement data that has been obtained using the various
instruments commercialized by [Fluke](https://www.fluke.com).

The information on the binary file format by [Fluke](https://www.fluke.com)
has been obtained by reverse engineering the official Windows software using
[Ghidra](https://ghidra-sre.org/).

FEATURES
--------
*python-fluke* can be used in two ways:
  - Using the embedded CLI (Command Line Interface) from a shell,
see [Usage](#cli)
  - As a library of a larger application, see the documentation.

Even though some information can be obtained from all Fluke binary files,
the measurement data can only be retrieved from `*.fvf` and `*.cur` files.

USAGE
-----
## Installation
After you downloaded *python-fluke*, no further installation steps are required.

## CLI
The CLI interface can be invoked using `python fluke --options`
in the project root directory (which contains this README).

Help can be obtained using
```sh
$ python fluke --help
```

## DOCUMENTATION
The documentation of main classes is provided as Sphinx reStructuredText,
which can be compiled into beautiful documentation by [Sphinx](http://www.sphinx-doc.org).

To compile the documentation you have to install Sphinx, which can be done using
```
pip install -U sphinx
```
If you are using Unix, you will also need `make`, which is generally provided
by default.

Then `cd` into the `doc` subdirectory and run e.g.
```
make html
```
to generate HTML documentation. The documentation is output in `doc/_build` by default.

LICENSING INFORMATION
---------------------
*python-fluke* is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

*python-fluke* is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with *python-fluke*. If not, see http://www.gnu.org/licenses/
