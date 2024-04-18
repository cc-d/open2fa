# Change Log

## 1.3.8

broadened the dependency range for pyshared dependency to prevent possible resolver warnings/issues

## 1.3.7

specified >= dependency range vs <=

## 1.3.6

Updated pyshared dependency to use new default_repr

## 1.3.4 / 1.3.5

Updated Documentation

## 1.3.3

added -f flag to delete command to skip confirmation

## 1.3.2

fixed bug with older python version typehints

## 1.3.1

added tests for terminal width/height auto-adjustment during generate

improve generate + test performance by avoiding sleep on last iteration if -r is specified

## 1.3.0

Completely refactored tests

Added various properties to open2fa object to more easily access the uuid/directory/etc

Added support for autodetecting name/secret from the add command without argument order being necessary (and tests for such)

Ensured test dirs are deleted after tests are run

Ensured info command now returns remote info if remote capabilitites have been init

Improved test coverage, up to 85% now

## 1.2.0

Fixed a bug with remote list where the secrets were being saved due to re-use of the same remote pull method. Added regression tests for this.

## 1.1.9

remote list command + tests

## 1.1.8

Fixed the remote examples in the README.md

## 1.1.7

changed package requirements range for logfunc requirement

## 1.1.6

fixed readme errors

## 1.1.5

Added support for argless use of open2fa add command, updated tests and documentation to reflect this

## 1.1.4

The entry_point func is now used by pyproject.toml to avoid the printing of the open2fa object to console when called from pypi installed open2fa

## 1.1.3

The open2fa object is now only returned by main if the return_open2fa kwarg is present and true.

## 1.1.2

Fixed bug where the open2fa object was being printed to console due to it being returned by main when called from the cli in some conditions

## 1.1.1

Reversed changelong order to be in descending order

Removed Dead code and improved test coverage

Improve test performance

## 1.1.0

Open2fa generate now automatically adjusts height/width of the generated codes to fit the terminal window

Added tests for this

## 1.0.9

Moved cli.py functions into open2fa class methods, specifically the remote init and info/status functions

Added named kwargs to the cli.py main() function

Ensured previous backwards compatibility with cli.py kwargs

Added tests for this

## 1.0.8

Handeled empty cli args in cli.py by printing help message

Added tests to verify this

Updated parse_args to return the parser instead of the args, and updated cli.py main() to reflect this

Added imports to **init**.py

## 1.0.7

Added test for --version and -v flags

Changed the way --version is handled in cli.py

## 1.0.6

Added --version and -v flags to display the version of open2fa

Also added set_version.py in repo root dir to update the version in open2fa/version.py and pyproject.toml

## 1.0.5

Fixed a bug where the -s flag for info/status was not working correctly

Updated tests/fixtures with a regression test added for this plus general test improvements, most tests were rewritten

## 1.0.4

cli.py main() now returns the open2fa object, this was to make testing easier.

Updated Open2FA Object attributes to reflect passed arguments to Open2FA() constructor over the config. values

Ensured some of the Open2FA Object attributes were assigned correctly

The -s tip text will no longer be displayed if -s was passed as an argument

Added more tests/fixtures

Pinned versions of dependencies in pyproject.toml and requirements.txt

Added changelog to repo and updated README.md to link to it
