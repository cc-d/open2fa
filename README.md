# open2fa

Open2FA is a 100% LIBRE tool for generating Two-Factor Authentication (2FA) TOTP codes.

As of now (v0.1.0) it is only a basic CLI, but in the future an api, webui, and .apk are planned to enable (optional, user-configured) 2FA across multiple devices in a manner that respects user privacy and freedom.

## File Locations and Environment Variables

**Secret Key Storage**: TOTP secret keys are stored in the directory specified by the `OPEN2FA_KEYDIR` environment variable. By default, this is set to `.open2fa` in the user's home directory, with secure permissions that only allow the user to read and write to/from the directory.

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
   open2fa add [org_name] [secret]
   ```

   Example Output:

   ```
   Added key: <Open2faKey path=/Users/user/.open2fa/NewOrgName.key, name=NewOrgName, secret=I...E, token=None, interval=-1>
   ```

2. **Delete a TOTP Secret**:

   ```bash
   open2fa delete [org_name]
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
   Org Name             Secret      Key Path
   NewOrgName           N...E       /Users/user/.open2fa/NewOrgName.key
   AnotherOrg           A...Z       /Users/user/.open2fa/AnotherOrg.key
   ```

4. **Generate 2FA Codes**:

   Generate codes for keys saved in the `OPEN2FA_KEYDIR` directory:

   ```bash
   open2fa generate

   <<< GENERATED 5 CODES >>>

   test2: 361070

   test3: 361070

   test: 393705

   testorg: 393705

   pypi: 214272
   ```

   **Generate 2FA code for a specific org**:

   ```bash
   open2fa generate [org_name]
   ```

   Example Output:

   ```
   <<< GENERATED 1 CODE >>>

   NewOrgName: 123456
   ```

   Tokens will continue to be generated until the user exits the program with `Ctrl+C`.

## How it Works

- **Secret Key Management**: Keys are added, retrieved, or deleted from the `OPEN2FA_KEYDIR`.
- **Token Generation**: Generates TOTP tokens using the `generate_totp_token` function in `utils.py`, which implements the standard TOTP algorithm.

## Testing

You can run the tests by running `pytest tests.py` in the root directory of the project
or by running the vscode pytest launch configuration with f5.

```
Name                    Stmts   Miss  Cover   Missing
-----------------------------------------------------
open2fa/__init__.py         0      0   100%
open2fa/cli.py             75     13    83%   103-104, 107-108, 128-130, 137, 145-146, 150-151, 155
open2fa/cli_config.py       4      0   100%
open2fa/cli_utils.py      149     33    78%   22-23, 90-95, 114-115, 132-144, 178, 212, 215-218, 221-222, 229-233, 277-278, 301, 304-306
open2fa/config.py           5      0   100%
open2fa/main.py             0      0   100%
open2fa/utils.py           16      0   100%
-----------------------------------------------------
TOTAL                     249     46    82%
```
