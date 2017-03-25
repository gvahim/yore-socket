import threading

from scapy.all import YO

from constants import CLIENT_STATE, LAST_PACKET_BUFFER_SIZE
from .. import serializer
from ..constants import SERIALIZER_CMD, BLOCKING, TIMEOUT_DEFAULT


class SocketClient(object):
    """
    A class that represents a YORE client.
    This class contains:
        A socket that is used as an IPC mechanism to transfer control 
        packages and data
        Variables that keep track of the in/out data on this channel
        LOCKS! A lot of locks to keep everything synchronized. We use an RLock 
        in cases where a thread may call upon the lock more than once and we 
        don't want to hang.
        Status variables that keep track of the client's status and connection 
        state.
    """

    def __init__(self, sock):
        """
        Initialize a new client. Expects only an IPC socket object as input.
        :param sock: socket object
        """
        self.protocol = -1
        self.sid_generated = -1
        self.sid_received = -1
        self.listen_port = -1
        self.last_packet_lock = threading.RLock()
        self.last_packet = []
        self.socket_state = CLIENT_STATE.NONE
        self.dest_port = -1
        self.yo_dest = -1
        self.initial_seq = -1
        self.seq = -1
        self.ack = -1
        self.fin_seq = -1
        self.fin_ack = -1
        self.fin_sid = -1
        self.incoming_data_lock = threading.RLock()
        self.incoming_data = ""
        self.incoming_data_with_address = []
        self.outgoing_data_lock = threading.RLock()
        self.outgoing_data = ""
        self.removable = False
        self.acknowledge_received_events = dict()

        self.error = None
        self.socket = sock
        self.waiting_for_response = 0
        self.debug_id = 0
        self.ipc_recv_buffer = ""
        self.serializer = serializer.Serializer()
        self.blocking = BLOCKING
        self.timeout = TIMEOUT_DEFAULT

    def finish_session(self, error=None):
        """
        This function finishes a client session. We have multiple things to 
        consider here:
        - Finishing gracefully and sending a FIN if possible
        - Sending an error if we did not finish the session gracefully
        - Closing the IPC socket
        - Setting this socket as removable so it will no longer be contained in 
          our client list
        :param error: ErrorTuple
        """
        self.fin_sid = self.sid_generated
        if self.fin_sid == -1:
            self.fin_sid = self.sid_received

        self.sid_generated = -1
        self.sid_received = -1
        self.error = error
        self.listen_port = -1
        self.initial_seq = -1
        self.fin_seq = self.seq
        self.fin_ack = self.ack
        self.seq = -1
        self.ack = -1

        # Wake up the ARQ task and finish it - we no longer require its services
        for event in self.acknowledge_received_events.values():
            event.set()

        with self.last_packet_lock:
            self.last_packet = []

        with self.incoming_data_lock:
            with self.outgoing_data_lock:
                self.incoming_data = ""
                self.outgoing_data = ""

        # If there's an error and the client is not in a waiting for fin state,
        # send the error code.
        # Otherwise, just close the socket gracefully
        if error is not None and self.socket_state != CLIENT_STATE.WAITING_FIN:
            self.send_ipc(self.serializer.RESULT_ERROR, 0xffffffff,
                          [error.code, error.description])
        else:
            self.send_ipc(self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.CLOSE,
                          [])

        self.socket_state = CLIENT_STATE.NONE

        self.socket.close()

        # We no longer wait for any kind of response after our session has ended
        self.waiting_for_response = 0

        # Mark this socket for removal
        self.removable = True

    def send_ipc(self, result, cmd, args):
        """
        A helper function that sends data over the IPC channel.
        Usually we'd like to send back a result to a client's action, 
        the requested CMD for which the result is relevant (to avoid mismatch), 
        and a list of args if necessary.
        :param result: to send
        :param cmd: to send
        :param args: to send
        """
        larges = list(args)
        larges.insert(0, cmd)
        data = self.serializer.serialize(result, larges)
        try:
            self.socket.send(data)
        except:
            self.removable = True

    def initiate_session(self, accept_params=None, send_scss=1):
        """
        Initiate a new session for the client. This takes care of all the YO/RE 
        state of the socket.
        It receives an optional Accept Parameters and Send Success.
        The accept parameters are relevant if a new client (Resocket) has woken 
        up from an accept function. It needs
        to notify us that it already has a session set up and wishes to register 
        itself in the ProtocolDaemon with
        the correct params. In this case, we return an accept success.
        The other use case is if a client has initiated a session with the 
        connect method, in which case
        we return a success value and take care of setting up the session.
        :param accept_params: to send
        :param send_scss: to send
        """
        # Handle a client that is initiated with accept parameters.
        if accept_params is not None:
            self.send_ipc(self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.ACCEPT,
                          accept_params)
            self.socket_state = CLIENT_STATE.INITIATING_CONNECTION
            self.seq = 0
            self.ack = 0
            self.sid_generated = -1
            self.sid_received = -1
            self.yo_dest = -1
            with self.last_packet_lock:
                self.last_packet = []
        else:
            # Handle a client that is initiated without accept
            # parameters (connect)
            self.seq = 0
            self.ack = 0
            self.sid_generated = -1
            self.socket_state = CLIENT_STATE.SESSION_ACTIVATED
            if send_scss:
                self.send_ipc(self.serializer.RESULT_SUCCESS,
                              SERIALIZER_CMD.CONNECT, ["CONNECT"])
            with self.last_packet_lock:
                self.last_packet = []

        self.waiting_for_response = 0

    def __add_last_packet(self, pkt):
        """
        Internal function
        Add packet to sent buffer
        :param pkt: str pkt to add to buffer
        """
        if not isinstance(pkt, str):
            pkt = str(pkt[YO])
        if len(self.last_packet) == LAST_PACKET_BUFFER_SIZE:
            self.last_packet = self.last_packet[1:]
        self.last_packet.append(pkt)

    def add_last_packet(self, pkt, lock):
        """
        Add packet to sent buffer
        :param pkt: str pkt to add to buffer
        :param lock: Use the SocketClient.last_packet_lock lock- should use if 
        not used before
        """
        if lock:
            with self.last_packet_lock:
                self.__add_last_packet(pkt)
        else:
            self.__add_last_packet(pkt)

    def __in_last_packet(self, pkt):
        """
        Internal function
        :param pkt: str pkt to check that in buffer. 
        if in the buffer - remove it
        :return: True if was in the buffer and remove / False
        """
        if not isinstance(pkt, str):
            pkt = str(pkt[YO])
        if pkt in self.last_packet:
            self.last_packet.remove(pkt)
            return True
        return False

    def in_last_packet(self, pkt, lock):
        """
        :param pkt: str pkt to check that in buffer. 
        if in the buffer - remove it
        :return: True if was in the buffer and remove / False
        :param lock: Use the SocketClient.last_packet_lock lock- should use if 
        not used before
        """
        if lock:
            with self.last_packet_lock:
                return self.__in_last_packet(pkt)
        else:
            return self.__in_last_packet(pkt)
