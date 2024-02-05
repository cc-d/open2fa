SECRET_ADDED = 'Added secret: {}'
SECRET_DELETED = 'Deleted key for {}'
SECRET_NOT_ADDED = 'Key not added.'
CONFIRM_REMOVE = 'Are you sure you want to remove {} {}? (y/n): '


INIT_EVAR_SET = 'Remote init environment variable already set.'
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
INFO_STATUS = (
    '\n' + _title_pad + ' Open2FA INFO/STATUS ' + _title_pad + '\n'
    '(add -s to show uncensored secrets)\n\n'
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
