# open2fa

[open2fa.liberfy.ai](https://open2fa.liberfy.ai) NOW LIVE

Open2FA is a 100% LIBRE tool for generating Two-Factor Authentication (2FA) (TOTP) codes, with optional, secure, remote sync/restore/etc capabilities, as well as optional webui 2FA code generation.

All code can be found at:

[CLI repo](https://github.com/cc-d/open2fa)

[API/WebUI repo](https://github.com/cc-d/open2fa-server)

For information as to how the remote capabilities work, see [open2fa.liberfi.ai](https://open2fa.liberfy.ai)

## Features

- **CLI 2FA Code Generation**: Generate 2FA codes from the command line from TOTP secret keys stored either locally or remotely.
- **Secure Remote Capabilitites**: All remotely stored TOTP secrets are stored encrypted and are only decrypted client side.
- **Easily restore TOTP secrets**: Easily transfer and restore TOTP secrets from any device from only a UUID
- **WebUI 2FA Code Generation**: Generate 2FA codes from the webui using the remotely stored encrypted TOTP secret keys from any device, even if the device does not have either the open2fa CLI or the TOTP secrets stored locally.
- **Host your own API**: You can easily choose to host your own open2fa server and use it with the open2fa CLI.
- **Open Source**: Open2FA is 100% open source and is both free as in freedom and free as in beer.

## Installation

Install the CLI using `pip`:

```bash
pip install open2fa
```

If wanting to do development work, install with dev dependencies:

```bash
pip install 'open2fa[dev]'
```

## Configuration

**Environment Variables**:

- `OPEN2FA_DIR`: The directory where TOTP secrets and the Open2FA UUID are stored. Defaults to `.open2fa` in the user's home directory.

- `OPEN2FA_API_URL`: The URL of the Open2FA API instance to use. Defaults to `https://open2fa.liberfy.ai`.

- `OPEN2FA_UUID` (Optional): Instead of using the `open2fa.uuid` file stored in `OPEN2FA_DIR`, you can set the `OPEN2FA_UUID` environment variable to the UUID you wish to use.

## Default File Locations

- **Secrets File**: The TOTP secrets are stored in `OPEN2FA_DIR/secrets.json`.
- **UUID File**: The Open2FA UUID is stored in `OPEN2FA_DIR/open2fa.uuid`, but can also be set using the `OPEN2FA_UUID` environment variable. This UUID is used to identify the user and encrypt/decrypt their remotely stored secrets.

## CLI Usage ( local )

You can see the full list of commands and options by running `open2fa -h` or `open2fa --help`.

**Add a TOTP Secret**:

```bash
open2fa add I65VU7K5ZQL7WB4E -n TESTKEY123
```

**Delete a TOTP Secret**:

```bash
open2fa delete -n TESTKEY123
```

**List All TOTP Secrets**:

```bash
open2fa list
```

Example Output:

```
Name         Secret
-------      -----
Secret1      I...E
Secret2      I...E
Secret3      A...B
```

To show the secret keys, use the `-s` flag:

```bash
open2fa list -s

Name       Secret
-------    ------
Secret1    I65VU7K5ZQL7WB4E
Secret2    I65VU7K5ZQL7WB4E
Secret3    I65VU7K5ZQL7WB4E
```

**Generate 2FA Codes**:

Generate codes for keys saved in `OPEN2FA_DIR/secrets.json`:

```bash
open2fa generate

Name       Code      Next Code
-------    ------    ---------
Secret1    490992    2.620
Secret2    490992    2.620
Secret3    216241    2.620
```

Tokens will continue to be generated until the user exits the program with `Ctrl+C`.

**Show Open2FA Info/Status/Secrets**:

```bash
open2fa info
```

Example Output:

```
========== Open2FA INFO/STATUS ==========
(add -s to show uncensored secrets)

Open2FA Directory: /Users/mym2/.open2fa
Open2FA Remote API URL: http://localhost:8000/api/v1
Number of secrets: 11
Open2FA UUID: 0...
Open2FA ID: X...
Open2FA Secret: Q...
```

## CLI Usage ( remote )

When initializing the remote capabilities of the open2fa CLI, a UUID will be generated and stored in `OPEN2FA_DIR/open2fa.uuid`. This UUID is used to identify the user and encrypt/decrypt their remotely stored secrets. As long as the user has access to this UUID, they can restore their TOTP secrets from any device, as well as generate 2FA codes from the webui.

For usage with the webui, both the Open2FA ID and the Open2FA Secret are required. These can be determined from `open2fa info` after initializing the remote capabilities of the open2fa CLI.

### **Initialize the Remote Capabilities of the Open2FA Client**:

```bash
open2fa init
```

Example Output:

```
open2fa remote init

Do you want to initialize remote capabilities of Open2FA? (y/n): y

Remote capabilities initialized with UUID: 0e4742ef-780b-406d-8651-7766cf67be3f
It is recommended to save this UUID somewhere safe and use as an environment variable OPEN2FA_UUID.

========== Open2FA INFO/STATUS ==========
(add -s to show uncensored secrets)

Open2FA Directory: /Users/mym2/.open2fa
Open2FA Remote API URL: http://localhost:8000/api/v1
Number of secrets: 11
Open2FA UUID: 0...
Open2FA ID: X...
Open2FA Secret: Q...
```

In this example:

- The Open2FA UUID is `0e4742ef-780b-406d-8651-7766cf67be3f`
- The Open2FA ID is `XF1628BGJeibVv8C9UacG4`
- The Open2FA Secret is `QGcst74V9JXnyBnQmWSoCx`

### Remote Commands

**Push TOTP Secrets to the remote server**:

```bash
open2fa push
```

**Pull TOTP Secrets from the remote server**:

```bash
open2fa pull
```

**Delete a TOTP Secret from the remote server**:

```bash
open2fa delete -n TESTKEY123
```

## Testing

You can run the tests by running `pytest tests.py` in the root directory of the project
or by running the vscode pytest launch configuration with f5.

```
---------- coverage: platform darwin, python 3.11.7-final-0 ----------
Name                   Stmts   Miss  Cover   Missing
----------------------------------------------------
open2fa/__init__.py        0      0   100%
open2fa/cli.py           151     21    86%   186, 198-214, 224, 273-279, 320-321, 330
open2fa/cli_utils.py      60      0   100%
open2fa/common.py         70      1    99%   123
open2fa/config.py         12      0   100%
open2fa/ex.py             15      2    87%   3, 19
open2fa/main.py          116     15    87%   64-65, 98-102, 105-108, 169, 212-213, 215-216, 221-234
open2fa/msgs.py           18      0   100%
open2fa/totp.py           30      0   100%
open2fa/utils.py          31     15    52%   20-25, 28, 52-63, 68
----------------------------------------------------
TOTAL                    503     54    89%
```

The tests are not complete, and need to be expanded.

## Contributing

Feel free to open an issue or pull request. If you are opening a pull request, please make sure to run the tests and ensure that the coverage does not decrease.

## License

MIT
