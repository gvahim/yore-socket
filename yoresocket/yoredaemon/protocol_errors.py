from collections import namedtuple

ErrorTuple = namedtuple('protocol_error', 'code description')

# A list of errors.
# IMPORTANT NOTE:
# This list has not been accepted into the YORE RFC yet! Please make sure that
# when a final version is out, these values will be validated!
SID_DOES_NOT_EXIST = ErrorTuple(1000, "SID does not exist!")
SYN_0_NO_DEST_PORT = ErrorTuple(1001, "Error: No destination port specified ony payload!")
DEST_PORT_IS_NOT_OPEN = ErrorTuple(1002, "Error: Destination port is not open!")
DEST_PORT_INIT_SEQ_MISMATCH = ErrorTuple(1003, "Error: Destination port and initial seq mismatch")
SYN_ACK_PAYLOAD_TOO_SMALL = ErrorTuple(1004, "Error: Syn-Ack payload is too small!")
DID_NOT_INIT_CONNECTION = ErrorTuple(1005, "Error: Did not initiate connection!")
ILLEGAL_FLAG_SID_0 = ErrorTuple(1006, "Error: Illegal flag for SID 0!")
INITIAL_SEQ_MUST_BE_0 = ErrorTuple(1007, "Error: Initial SEQ must be 0!")
INITIAL_ACK_MUST_BE_0 = ErrorTuple(1008, "Error: Initial ACK must be 0!")
SYN_IS_ILLEGAL_AFTER_SESSION_INITIATION = ErrorTuple(1009, "Error: SYN is illegal after session initiation!")
SYN_ACK_IS_ILLEGAL_AFTER_SESSION_INITIATION = ErrorTuple(1010, "Error: SYN ACK is illegal after session initiation!")
INITIALIZATION_DIDNT_FINISH = ErrorTuple(1011, "Error: Initialization didn't finish, description = cannot ack!")
DATA_IS_BIGGER_THAN_64_BYTES = ErrorTuple(1012, "Error: Data is bigger than 64 bytes!")
INIT_DIDNT_FINISH_FIN_IS_ILLEGAL = ErrorTuple(1013, "Error: Initialization didn't finish - FIN is illegal!")
ILLEGAL_FLAG_COMBINATION = ErrorTuple(1014, "Error: Illegal flag combination!")
ACK_TIMEOUT = ErrorTuple(1015, "Error: Timed out, description = No ACK reply")
