SECRET_ADDED = '\nADDED NEW SECRET: {} {}\n'
SECRET_DELETED = 'Deleted key for {}'
SECRET_NOT_ADDED = 'Key not added.'
CONFIRM_REMOVE = 'Are you sure you want to remove {} {}? (y/n): '


INIT_UUID_SET = 'Open2FA already initialized with an UUID'
INIT_FOUND_UUID = 'Found existing UUID file.'
INIT_CONFIRM = (
    'Do you want to initialize remote capabilities of Open2FA? (y/n): '
)
INIT_SUCCESS = (
    '\nRemote capabilities initialized with UUID: {}\n'
    'It is recommended to save this UUID somewhere safe '
    'and use as an environment variable OPEN2FA_UUID.'
)
INIT_FAIL = 'Remote initialization cancelled.'


DEL_NO_NAME_SECRET = 'No secret OR name provided to delete.'
DEL_SUCCESS = 'Deleted {} secret(s).'

ADD_ALREADY_EXISTS = (
    'Secret {} already exists with name {}, overwriting? (y/n): '
)

_title_pad = '=' * 10

INFO_SEC_TIP = '(add -s to show uncensored secrets)'

INFO_STATUS = (
    '\n' + _title_pad + ' Open2FA INFO/STATUS ' + _title_pad + '\n'
    '' + INFO_SEC_TIP + '\n\n'
    'Open2FA Directory: {}\n'
    'Open2FA Remote API URL: {}\n'
    'Number of secrets: {}\n'
    'Open2FA UUID: {}\n'
    'Open2FA ID: {}\n'
    'Open2FA Secret: {}\n'
)

PULL_SUCCESS = 'Pulled {} secret(s) from remote.'
PUSH_SUCCESS = 'Pushed {} secret(s) to remote.'


DEL_MIA_NAME_AND_SEC = 'No name or secret provided to delete.'
DEL_SUCCESS = 'Deleted {} secret(s).'

VERSION = 'Open2FA version: {}'

GEN_CODES_NOT_SHOWN = '... [{}] codes not shown ...'


ADD_NO_NAME_SEC = 'open2fa add was called without name or secret.'
ADD_SEC_PROMPT = 'Enter TOTP secret: '
ADD_NAME_PROMPT = 'Enter name for secret: '
ADD_INVALID_SECRET = 'Invalid TOTP secret: {} enter a valid secret.'
ADD_SEC_NAME = '\nAdded TOTP secret: {} with name {}\n'

CTRL_C = 'Press Ctrl+C to exit... '
SIGINT_MSG = '(SIGINT) Exiting...'
