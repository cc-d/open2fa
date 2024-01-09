# open2fa

Open2FA CLI is a 100% LIBRE command-line tool for generating Two-Factor Authentication (2FA) TOTP codes. It's designed for simplicity and security, allowing users to manage and generate TOTP codes efficiently and securely across multiple devices.

## File Locations and Environment Variables

**Secret Key Storage**: TOTP secret keys are stored in the directory specified by the `OPEN2FA_KEYDIR` environment variable. By default, this is set to `.open2fa` in the user's home directory.

## Installation

Install the CLI using `pip`:

```bash
pip install open2fa
```

## CLI Usage

1. **Add a TOTP Secret**:
   ```bash
   open2fa add [org_name] [secret]
   ```
2. **Delete a TOTP Secret**:
   ```bash
   open2fa delete [org_name]
   ```
3. **List TOTP Secrets**:
   ```bash
   open2fa list
   ```
4. **Generate a TOTP Code**:
   ```bash
   open2fa generate [org_name]
   ```

## How it Works

- **Argument Parsing**: The CLI parses user commands and arguments using `argparse`.
- **Secret Key Management**: Keys are added, retrieved, or deleted from the `OPEN2FA_KEYDIR`.
- **Token Generation**: Generates TOTP tokens using the `generate_totp_token` function in `utils.py`, which implements the standard TOTP algorithm.

## Usage Example

```
(venv) mym2@Carys-MacBook-Pro open2fa % ./open2fa/cli.py -h
usage: cli.py [-h] {add,a,delete,d,generate,g,list,l} ...

open2fa CLI: simple 2FA CLI interface

positional arguments:
  {add,a,delete,d,generate,g,list,l}
    add (a)             Add a new TOTP secret key for an organization
    delete (d)          Delete a TOTP secret key for an organization
    generate (g)        Generate a TOTP code for an organization
    list (l)            List TOTP keys

options:
  -h, --help            show this help message and exit
```

List all TOTP secrets:

```
(venv) py3 -m open2fa.cli l

Org Name             Secret      Key Path
test_org             t...t       /Users/mym2/.open2fa/test_org.key
test2                I...E       /Users/mym2/.open2fa/test2.key
test3                I...E       /Users/mym2/.open2fa/test3.key
test                 J...P       /Users/mym2/.open2fa/test.key
testorg              J...P       /Users/mym2/.open2fa/testorg.key
addelete             J...P       /Users/mym2/.open2fa/addelete.key
zhvufwfnfy           J...P       /Users/mym2/.open2fa/zhvufwfnfy.key

```

Add a new TOTP secret:

```
(venv) py3 -m open2fa.cli a NewOrgName JBSWY3DPEHPK3PXP
Added key: <Open2faKey: neworgname>
(venv) py3 -m open2fa.cli l | grep 'neworgname'
neworgname           J...P       /Users/mym2/.open2fa/neworgname.key
```

Generate a single TOTP code:

```
(venv) py3 -m open2fa.cli g -r 1
Error generating token for 'test_org': Incorrect padding

<<< GENERATED 7 CODES >>>

test2: 918215

test3: 918215

test: 597377

testorg: 597377

neworgname: 597377

addelete: 597377

zhvufwfnfy: 597377
```

Continuous generation example:

```
(venv) py3 -m open2fa.cli g
Error generating token for 'test_org': Incorrect padding

<<< GENERATED 7 CODES >>>

test2: 918215

test3: 918215

test: 597377

testorg: 597377

neworgname: 597377

addelete: 597377

zhvufwfnfy: 597377


<<< GENERATED 7 CODES >>>


test2: 706572

test3: 706572

test: 556351

testorg: 556351

neworgname: 556351

addelete: 556351

zhvufwfnfy: 556351

```

## Testing

You can run the tests by running `pytest` in the root directory of the project
or by running the vscode pytest launch configuration with f5.

```

---------- coverage: platform darwin, python 3.11.5-final-0 ----------
Name Stmts Miss Cover Missing

---

open2fa/**init**.py 0 0 100%
open2fa/cli.py 80 14 82% 102-103, 106-107, 127-130, 136, 150-151, 155-156, 160
open2fa/cli_utils.py 140 28 80% 21-22, 89-93, 111, 128-139, 173, 198, 201-204, 207-208, 215-219, 263-264, 274-275
open2fa/config.py 5 0 100%
open2fa/main.py 0 0 100%
open2fa/utils.py 16 0 100%

---

TOTAL 241 42 83%

```

```

```
