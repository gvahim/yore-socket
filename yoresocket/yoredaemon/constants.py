# enum class creation
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)


# The various YO protocol opcodes.
OPCODE = enum(PING=0, PONG=1, RE=2, RAW=0XFF)

# RE Flags - SAFE - Syn, Ack, Fin, Error
FLAG = enum(SYN=1, ACK=2, FIN=4, ERR=8)

# The different states a Resocket client can have.
CLIENT_STATE = enum('NONE', 'LISTEN', 'INITIATING_CONNECTION', 'INITIATING_SESSION',
                    'SESSION_ACTIVATED', 'WAITING_FIN', 'RECEIVED_FIN')

# Buffer of sent packet size
LAST_PACKET_BUFFER_SIZE = 100

TIMEOUT = 10
TIMEOUT_CHECK = 0.1