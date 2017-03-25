# Socket possible protocols
SOCK_RE = 0
SOCK_RAW = 1

NON_BLOCKING = 0
BLOCKING = 1

# The ProtocolDaemon IPC parameters. We will always want 127.0.0.1 since
# the ProtocolDaemon acts as a local "driver" of sorts.
RESOCKET_DAEMON_HOST = "127.0.0.1"
RESOCKET_DAEMON_DEFAULT_PORT = 9996


# enum class creation
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)


# The various Resocket state. Hardcoded values (internal enum).
STATE = enum('NONE', 'BOUND', 'LISTEN', 'CONNECTION_ESTABLISHED')

# A list of commands sent by the user (between the daemon and the api)
SERIALIZER_CMD = enum('EMPTY',
                      'SENDTO',
                      'RECVFROM',
                      'RECV_EMPTY',
                      'CLOSE',
                      'CONNECT',
                      'BIND',
                      'LISTEN',
                      'ACCEPT',
                      'SEND',
                      'RECV',
                      'EXIST',
                      'SET_PROTOCOL',
                      'SENDPING',
                      'SET_BLOCKING',
                      'SET_TIMEOUT',
                      'GET_SID',
                      'ADD_TO_ACK_COUNTER',
                      'ADD_TO_SEQ_COUNTER')

TIMEOUT_DEFAULT = 8
