# open2fa

Open2FA is a 100% LIBRE tool for generating Two-Factor Authentication (2FA) TOTP codes.

As of now (v0.1.0) it is only a basic CLI, but in the future an api, webui, and .apk are planned to enable (optional, user-configured) 2FA across multiple devices in a manner that respects user privacy and freedom.

## File Locations and Environment Variables

**Secret Key Storage**: TOTP secret keys are stored in the directory specified by the `OPEN2FA_DIR` environment variable. By default, this is set to `.open2fa` in the user's home directory, with secure permissions that only allow the user to read and write to/from the directory.

## Installation

Install the CLI using `pip`:

```bash
pip install open2fa
```

Install with dev dependencies:

```bash
pip install 'open2fa[dev]'
```

## CLI Usage

1. **Add a TOTP Secret**:

   ```bash
   open2fa add secret I65VU7K5ZQL7WB4E -n aTESTTESTTESTTESTTESTTEST334434
   ```

   Example Output:

   ```
   Added secret: aTESTTESTTESTTESTTESTTEST334434 I...E
   ```

2. **Delete a TOTP Secret**:

   ```bash
   open2fa delete [name?] [secret?]
   ```

   Example Output:

   ```
   Deleted key for 'NewOrgName'
   ```

3. **List TOTP Secrets**:

   ```bash
   open2fa list
   ```

   Example Output:

   ```
   Name                            Secret
   -------------------------       -----
   aTESTTESTTESTTESTTESTTEST       I...E
   None                            I...E
   pypi                            A...B
   TESTTESTTESTTESTTESTTEST        I...E
   TESTTESTTESTTESTTESTTEST2       I...E
   ```

   To show the secret keys, use the `-s` flag:

   ```bash
   open2fa list -s

   Name                                    Secret
   -------------------------------    --------------------------------
   aTESTTESTTESTTESTTESTTEST          I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST3         I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST33        I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST334       I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST3344      I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST33443     I65VU7K5ZQL7WB4E
   aTESTTESTTESTTESTTESTTEST334434    I65VU7K5ZQL7WB4E
   None                               I65VU7K5ZQL7WB4E
   pypi                               CENSORED
   TESTTESTTESTTESTTESTTEST           I65VU7K5ZQL7WB4E
   TESTTESTTESTTESTTESTTEST2          I65VU7K5ZQL7WB4E
   ```

4. **Generate 2FA Codes**:

   Generate codes for keys saved in `OPEN2FA_DIR/secrets.json`:

   ```bash
   open2fa generate
   Name                         Code      Next Code
   -------------------------    ------    ---------
   aTESTTESTTESTTESTTESTTEST    490992    2.620
   None                         490992    2.620
   pypi                         216241    2.620
   TESTTESTTESTTESTTESTTEST     490992    2.620
   TESTTESTTESTTESTTESTTEST2    490992    2.620
   ```

   Tokens will continue to be generated until the user exits the program with `Ctrl+C`.

## How it Works

- **Secret Key Management**: Keys are added, retrieved, or deleted from the `OPEN2FA_DIR`.
- **Token Generation**: Generates TOTP tokens using the `generate_totp_2fa_code` function in `utils.py`, which implements the standard TOTP algorithm.

## Testing

You can run the tests by running `pytest tests.py` in the root directory of the project
or by running the vscode pytest launch configuration with f5.

```
---------- coverage: platform darwin, python 3.11.7-final-0 ----------
Name                   Stmts   Miss  Cover   Missing
----------------------------------------------------
open2fa/__init__.py        0      0   100%
open2fa/cli.py            79     13    84%   168, 171-192, 196-197, 204
open2fa/cli_utils.py      40      0   100%
open2fa/common.py         70     27    61%   32-34, 37, 46-57, 66-77, 88-98, 101, 121, 124
open2fa/config.py         11      2    82%   11-12
open2fa/ex.py              3      1    67%   3
open2fa/main.py           55      4    93%   56-57, 90, 101
open2fa/msgs.py            4      0   100%
open2fa/totp.py           30      1    97%   24
open2fa/utils.py           3      0   100%
----------------------------------------------------
TOTAL                    295     48    84%
```
