"""
Author: YochaiE
Date: 08.02.16

YORE resocket.py file.

This script is the FRONT END for the developer / student. It contains a RESOCKET
class that mimics the behaviour of any other python socket.
The resocket class exposes CONNECT, LISTEN, BIND, SEND, RECV, ACCEPT, CLOSE
functions that a user can use in order to communicate. All the other functions
are considered internal and are not supposed to be used by the user.
As this is only the front end, all the calls are transferred via IPC
(Inter-process communication) to a daemon that handles the actual YORE protocol.
In our case - a python script.

The IPC is done over normal TCP sockets using hardcoded port 9996. The protocol
is proprietary, but very simple - it contains a TYPE dword, LENGTH dword and
DATA (that's also in a TLV format).

A basic state sanity is verified for each user call.

NOTES:
    State checking might not 100% tight. Further checking of edge cases is
    recommended.
    IPC Serialization is not handling edge cases where data is corrupted. We
    assume one will fiddle with it, but it's not a good practice.
"""

import struct
import socket
import serializer
import threading

from YOREException import YOREDaemonToAPICommunicationError, YOREUnsupportedProtocolAction, YOREDaemonToAPIValueError, \
    YOREProtocolError, YOREException, YORETimeoutException
from constants import SOCK_RE, SOCK_RAW, STATE, RESOCKET_DAEMON_DEFAULT_PORT, \
    RESOCKET_DAEMON_HOST, SERIALIZER_CMD, BLOCKING, NON_BLOCKING, TIMEOUT_DEFAULT


class Resocket(object):
    """
    The Resocket class that can be used by users.
    Must run a the daemon in a different process before using this.

    Thread safe notes - this class is thread safe only in the non blocking mode.
    (in the blocking mode you may have  to wait to other thread recv \ recvfrom response)
    """

    def __init__(self, protocol, accept_params=None, daemon_port=None):
        """
        Open a socket of the given type.
        A socket object represents one endpoint of a network connection.

        :param protocol: SOCK_RE or SOCK_RAW.
        :param accept_params: Accept params are relevant for cases where a socket is "born" out of an accept command
        :param daemon_port: The daemon localhost TCP Port. Use only if you use multiple YORE Daemons on the same
        computer (if you want to have multiple YO addresses on the same computer).

        """
        # A Resocket must be initialized with a selected protocol (RE/Raw/etc.),
        # and can be initialized with "accept params". Accept params are relevant for
        # cases where a socket is "born" out of an accept command (just like real sockets).
        # See the server script for an example about accepted socket.

        self.main_lock = threading.RLock()

        self.daemon_port = daemon_port if daemon_port is not None else RESOCKET_DAEMON_DEFAULT_PORT

        self.__protocol = protocol

        # Create an IPC Serializer helper class.
        self.__serializer = serializer.Serializer()

        # Create our IPC socket and connect to the YORE ProtocolDaemon.
        self.__ipc = socket.socket(socket.AF_INET)
        self.__connect_to_daemon()

        # If the socket has accept parameters, initialize it with them.
        if accept_params:
            self.__yo_dest = accept_params[0]
            self.re_port = accept_params[1]
            self.__sid = accept_params[2]
            self.last_packet = accept_params[3]
            self.__blocking = accept_params[4]
            self.__timeout = accept_params[5]
            self.__state = STATE.CONNECTION_ESTABLISHED

            # Notify the ProtocolDaemon of the new socket existence.
            # This is necessary since the original server socket still exists, and
            # when a new connection is created, a new socket is allocated for it.
            # The ProtocolDaemon has to know it has a new socket which performs the actual session.
            self.__notify_accepted_socket()
        else:
            self.__yo_dest = None
            self.re_port = None
            self.__sid = None
            self.__state = STATE.NONE
            self.__set_protocol()
            self.__blocking = BLOCKING
            self.__timeout = TIMEOUT_DEFAULT

    def is_alive(self):
        """
        :return: returns True/False if the connection is on/off
        """
        with self.main_lock:
            if self.__state == STATE.NONE:
                return False
            try:
                self.__send_and_recv_ipc(SERIALIZER_CMD.EMPTY, [])
            except:
                self.__state = STATE.NONE
                return False
            return True

    def connect(self, address):
        """
        Connect the socket to a remote address.  For IP sockets, the address
        is a pair (host, port).

        Please note: only support SOCK_RE mode,
        A socket may only connect if it's unbound (clean socket)

        :param address: YO remote address ('A.B')
        """
        with self.main_lock:
            if self.__protocol != SOCK_RE:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RE",
                                                    SOCK_RE, self.__protocol)
            if self.__state != STATE.NONE:
                raise YOREUnsupportedProtocolAction("Error, must be in STATE %d to connect" % STATE.NONE,
                                                    STATE.NONE, self.__state)
            host, port = address
            self.__yo_dest = host

            if type(host) is str:
                a, b = host.split(".")
                self.__yo_dest = struct.unpack(">H", struct.pack(">BB", int(a), int(b)))[0]
            self.re_port = port

            args = [self.__yo_dest, self.re_port]

            return self.__safe_send_and_recv_ipc(SERIALIZER_CMD.CONNECT, STATE.NONE, args,
                                             upgrade_state_if_successful=STATE.CONNECTION_ESTABLISHED)[0]
    @staticmethod
    def _convert_num_to_yoip(num):
        a, b = struct.unpack(">BB", struct.pack(">H", num))
        return str(a) + '.' + str(b)

    def get_yo_dest(self):
        """
        get the dest YO address
        :return: dest YO address. None if not set.
        """
        return self._convert_num_to_yoip(self.__yo_dest) if isinstance(self.__yo_dest,int) else self.__yo_dest

    def listen(self, backlog=1):
        """
        Socket listen command - listens for new connections.

        Please note: only support SOCK_RE mode,
        A socket may only listen if it's bound to an address

        :param backlog: At the moment, we don't care about listen "backlog" functionality, and
        we only maintain this parameter to keep the listen identical to a normal
        socket's listen.
        """
        with self.main_lock:
            if self.__protocol != SOCK_RE:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RE",
                                                    SOCK_RE, self.__protocol)
            return self.__safe_send_and_recv_ipc(SERIALIZER_CMD.LISTEN, STATE.BOUND, [backlog],
                                                 upgrade_state_if_successful=STATE.LISTEN)[0]

    def bind(self, address):
        """
        Bind the socket to a local address.  The address is a
        pair (YO host, RE port); the host must refer to the local host.
        For raw packet sockets the address is a tuple (Yo host, 0)

        Please note: A socket may only bind if it's unbound (clean socket)

        :param address: YO self address ('A.B')
        """
        # Socket bind command - binds the socket to a YO address and RE dest port.
        # Again, we use address as a dictionary, like the original socket API.
        with self.main_lock:
            host, port = address
            self.re_port = port

            # If the host is a string, convert it into a numeric form
            if type(host) is str:
                a, b = host.split(".")
                host = struct.unpack(">H", struct.pack(">BB", int(a), int(b)))[0]

            return self.__safe_send_and_recv_ipc(SERIALIZER_CMD.BIND, STATE.NONE, [host, port],
                                                 upgrade_state_if_successful=STATE.BOUND)[0]

    def recv(self, buffer_size):
        """
        Receive command. This function is blocking until there's data to receive.
        Notice that like real sockets, stating buffer_size does not necessarily mean the whole
        buffer is going to get filled. When the ProtocolDaemon has data to send back, it will do so.
        The buffer_size indicates the maximum data size that the user is able to chew at the moment.
        NON-BLOCKING MODE: May return false if disconnected
        BLOCKING MODE: May raise YOREException if disconnected

        Please note: only support SOCK_RE mode
        :param buffer_size: max buffer length to receive
        :return: buffer
        """
        with self.main_lock:
            if self.__protocol != SOCK_RE:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RE",
                                                    SOCK_RE, self.__protocol)

            (res, data) = self.__safe_send_and_recv_ipc(SERIALIZER_CMD.RECV, STATE.CONNECTION_ESTABLISHED,
                                                        [buffer_size], return_command_types=(SERIALIZER_CMD.RECV,
                                                                                             SERIALIZER_CMD.CLOSE,
                                                                                             SERIALIZER_CMD.RECV_EMPTY))
            if data[0] == SERIALIZER_CMD.RECV_EMPTY:
                if self.__blocking == BLOCKING:
                    raise YORETimeoutException
                else:
                    return False

            res = (data[1] if data[0] == SERIALIZER_CMD.RECV else False) if res else False

            # addition - add exception
            if self.__blocking == BLOCKING and res == False:
                raise YOREException
            return res

    def recvfrom(self, buffer_size):
        """
        Receive From command. This function is blocking until there's data to receive.
        Notice that like real sockets, stating buffer_size does not necessarily mean the whole
        buffer is going to get filled. When the ProtocolDaemon has data to send back, it will do so.
        The buffer_size indicates the maximum data size that the user is able to chew at the moment.
        NON-BLOCKING MODE: May return false if disconnected
        BLOCKING MODE: May raise YOREException if disconnected

        Please note: only support SOCK_RAW mode
        :param buffer_size: max buffer length to receive
        :return: (address, buffer)
        """
        with self.main_lock:
            if self.__protocol != SOCK_RAW:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RAW",
                                                    SOCK_RAW, self.__protocol)

            (res, data) = self.__safe_send_and_recv_ipc(SERIALIZER_CMD.RECVFROM, STATE.BOUND,
                                                        [buffer_size], return_command_types=(SERIALIZER_CMD.RECVFROM,
                                                                                             SERIALIZER_CMD.RECV_EMPTY,
                                                                                             SERIALIZER_CMD.CLOSE))

            if data[0] == SERIALIZER_CMD.RECV_EMPTY:
                if self.__blocking == BLOCKING:
                    raise YORETimeoutException
                else:
                    return False

            res = ((data[1], data[2]) if data[0] == SERIALIZER_CMD.RECVFROM else False) if res else False

            # addition - add exception
            if self.__blocking == BLOCKING and res == False:
                raise YOREException
            return res

    def send(self, send_data):
        """
        Send data command.
        May raise YOREException if disconnected

        Please note: only support SOCK_RE mode
        :param send_data: buffer as string. if  is empty - ignores and return None
        """
        with self.main_lock:
            if send_data is None or send_data == '':
                return None

            if self.__protocol != SOCK_RE:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RE",
                                                    SOCK_RE, self.__protocol)

            res = self.__safe_send_and_recv_ipc(SERIALIZER_CMD.SEND, STATE.CONNECTION_ESTABLISHED, [send_data])[0]

            # addition - add exception
            if res == False or res is None:
                raise YOREException
            return res

    def sendto(self, address, send_data):
        """
        Sendto data command
        May raise YOREException if disconnected

        Please note: only support SOCK_RAW mode
        :param address: YO remote address ('A.B')
        :param send_data: buffer as string. if  is empty - ignores and return None
        """
        with self.main_lock:
            if send_data is None or send_data == '':
                return None

            if self.__protocol != SOCK_RAW:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RAW",
                                                    SOCK_RAW, self.__protocol)

            res = self.__safe_send_and_recv_ipc(SERIALIZER_CMD.SENDTO, None, [address, send_data])[0]

            # addition - add exception
            if res == False or res is None:
                raise YOREException
            return res


    def accept(self):
        """
        Accept command.
        On success, This command returns a new Resocket (initialized with the
        correct YO address, destination port and session id), and the YO

        Please note: only support SOCK_RE mode
        """
        with self.main_lock:
            if self.__protocol != SOCK_RE:
                raise YOREUnsupportedProtocolAction("Unexpected cmd for this socket. Use with SOCK_RE",
                                                    SOCK_RE, self.__protocol)

            (res, data) = self.__safe_send_and_recv_ipc(SERIALIZER_CMD.ACCEPT, STATE.LISTEN, [])

            if not res:
                return None
            yo_addr, self.__yo_dest, re_port, self.__sid, last_packet = data[1:6]
            accept_parameters = [self.__yo_dest, re_port, self.__sid, last_packet, self.__blocking, self.__timeout]
            return Resocket(SOCK_RE, accept_params=accept_parameters, daemon_port=self.daemon_port), self.__yo_dest

    def close(self):
        """
        Close command.
        If using SOCK_RE, The other side of the connection should know that the session is terminated
        """
        # Tells the ProtocolDaemon to close the connection - so that the other side of the
        # connection will know that the session is terminated, and close the IPC
        # connection.
        with self.main_lock:
            self.__state = STATE.NONE
            try:
                self.__send_ipc(SERIALIZER_CMD.CLOSE, [])
            except YOREDaemonToAPICommunicationError:
                pass
            self.__ipc.close()

    def setblocking(self, blocking):
        """
        set the blocking mode for recv and recvall
        :param blocking: BLOCKING (0) or NON_BLOCKING (1)
        :return: True if set. else false
        """
        with self.main_lock:
            if blocking in (BLOCKING, NON_BLOCKING):
                self.__blocking = blocking
                self.__send_and_recv_ipc(SERIALIZER_CMD.SET_BLOCKING, [blocking])
                return True
            return False

    def settimeout(self, timeout):
        """
        set the timeout blocking mode for recv commands in seconds
        :param timeout: seconds to wait
        """
        with self.main_lock:
            self.__timeout = timeout
            self.__send_and_recv_ipc(SERIALIZER_CMD.SET_TIMEOUT, [timeout])


    def add_to_ack_counter(self, number_to_add):
        """
        change the internal ACK counter of the socket by adding number to it (modulo 256)
        NOTE: This is advanced level function that can make the socket unstable. use with caution!
        :param number_to_add: number to add
        """
        with self.main_lock:
            self.__send_and_recv_ipc(SERIALIZER_CMD.ADD_TO_ACK_COUNTER, [number_to_add])

    def add_to_seq_counter(self, number_to_add):
        """
        change the internal SEQ counter of the socket by adding number to it (modulo 256)
        NOTE: This is advanced level function that can make the socket unstable. use with caution!
        :param number_to_add: number to add
        """
        with self.main_lock:
            self.__send_and_recv_ipc(SERIALIZER_CMD.ADD_TO_SEQ_COUNTER, [number_to_add])

    def getsid(self):
        """
        get the current session SID (-1 if in no session)
        :return: SID number
        """
        with self.main_lock:
            (res, data) = self.__send_and_recv_ipc(SERIALIZER_CMD.GET_SID, [])
            return data[1]


    def __connect_to_daemon(self):
        """
        Connects to the IPC ProtocolDaemon
        """
        try:
            self.__ipc.connect((RESOCKET_DAEMON_HOST, self.daemon_port))
        except socket.error as e:
            if e.errno == 10061:
                raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Did you run run_daemon()?", 10061)
            else:
                raise
        except Exception:
            raise

    def __set_protocol(self):
        """
        The ProtocolDaemon has to know the protocol type
        (Theirs no need to use this function if __notify_accepted_socket is called
        - because then it is sure RE)
        """
        args = [self.__protocol]
        self.__send_and_recv_ipc(SERIALIZER_CMD.SET_PROTOCOL, args)

    def __notify_accepted_socket(self):
        """
        Notify the YORE ProtocolDaemon that this is is an "existing" socket, born out
        of an accept command.
        """
        # The ProtocolDaemon has to know the dest address, the Session ID, and the last packet
        # (for filtering purposes)
        args = [self.__yo_dest, self.__sid, self.last_packet, self.__blocking, self.__timeout]
        self.__send_and_recv_ipc(SERIALIZER_CMD.EXIST, args)

    def __safe_send_and_recv_ipc(self, command_type, should_be_in_state, args, upgrade_state_if_successful=None,
                                 return_command_types=None):
        """
        send and recv ipc with many security checks according to the parameters.

        for example: to send ipc of "SEND" command we will send SERIALIZER_CMD.SEND and expect to get
        reply with the same enum. Also we demand that our state will be STATE.CONNECTION_ESTABLISHED

        can raise YOREUnsupportedProtocolAction, YOREDaemonToAPIValueError

        :param command_type: SERIALIZER_CMD enum - the cmd to send
        :param should_be_in_state: STATE enum - what self.state should be
        :param args: [data] - to send to the ipc
        :param upgrade_state_if_successful: STATE enum - if everything goes fine - change self.state to new one
        :param return_command_types: SERIALIZER_CMD enum list - what to expect to receive -
        - if None will use the command_type instead
        :return: (True, [data]) or (False,None)
        """
        if return_command_types is None:
            return_command_types = [command_type]

        # Failure check
        if should_be_in_state is not None and self.__state != should_be_in_state:
            raise YOREUnsupportedProtocolAction("Error, must be in STATE %d to connect" % should_be_in_state,
                                                should_be_in_state, self.__state)

        # The real job is in here - send the ipc to the daemon and receive an answer

        result, data = self.__send_and_recv_ipc(command_type, args)

        # Failure checks
        if result == self.__serializer.RESULT_ERROR:
            if self.__state != STATE.NONE:
                self.__state = STATE.NONE
                self.__ipc.close()
            if len(data) == 3:
                raise YOREProtocolError(data[1], data[2])
            elif len(data) == 2:
                raise YOREProtocolError(data[1])
            else:
                raise YOREProtocolError()
        elif result != self.__serializer.RESULT_SUCCESS:
            self.__state = STATE.NONE
            self.__ipc.close()
            raise YOREDaemonToAPIValueError(
                "Got an unexpected cmd result %d for cmd %d. closing socket!" % (result, command_type),
                result, command_type)
        if command_type not in return_command_types:
            self.__state = STATE.NONE
            self.__ipc.close()
            raise YOREDaemonToAPIValueError(
                "Got an unexpected cmd type %d for cmd %d. closing socket!" % (data[0], command_type),
                [0], command_type)

        # If we got to here - success!
        if upgrade_state_if_successful is not None:
            self.__state = upgrade_state_if_successful
        return True, data

    def __send_and_recv_ipc(self, cmd, args):
        self.__send_ipc(cmd, args)
        res = self.__recv_ipc()
        #print '<', res, '>' , '(', cmd, args, ')'
        return res

    def __recv_ipc(self):
        """
        DO NOT USE THIS FUNCTION - use __send_and_recv_ipc

        This function receives an IPC from the socket, usually in response to action we initialize.
        :return: data array
        """

        # Receive 8 bytes of IPC header - TYPE (success/error) and LENGTH.
        # This lets us know how much DATA we expect on this IPC.
        recv_data = ""
        while len(recv_data) < self.__serializer.TLV_HEADER_SIZE:
            try:
                recv_data += self.__ipc.recv(self.__serializer.TLV_HEADER_SIZE - len(recv_data))
            except socket.error as e:
                self.__state = STATE.NONE
                self.__ipc.close()
                if e.errno == 10053:
                    raise YOREDaemonToAPICommunicationError("Daemon closed the connection", 10053)
                if e.errno == 10054:
                    raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Did you close it?", 10054)
                if e.errno == 10061:
                    raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Use run_daemon()", 10061)
                else:
                    raise
            except Exception:
                raise

        # Receive the amount of data specified in the header
        data_len = struct.unpack("<I", recv_data[4:8])[0]
        while len(recv_data) < data_len + 8:
            try:
                recv_data += self.__ipc.recv(data_len + 8 - len(recv_data))
            except socket.error as e:
                if e.errno == 10053:
                    raise YOREDaemonToAPICommunicationError("Daemon closed the connection", 10053)
                if e.errno == 10054:
                    raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Did you close it?", 10054)
                if e.errno == 10061:
                    raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Use run_daemon()", 10061)
                else:
                    raise
            except Exception:
                raise

        # Universalize the IPC to a RESULT and a list of ARGS
        return self.__serializer.deserialize(recv_data)

    def __send_ipc(self, cmd, args):
        """
        DO NOT USE THIS FUNCTION - use __send_and_recv_ipc
        (we almost always expect some return value.)

        This function sends an IPC to the ProtocolDaemon.
        It specifies the command and an optional list of arguments that
        comes with it.
        :param cmd: SERIALIZER_CMD enum
        :param args: array
        """
        # Serialize the command and args, send them.
        data = self.__serializer.serialize(cmd, args)
        try:
            self.__ipc.send(data)
        except socket.error as e:
            if e.errno == 10053:
                raise YOREDaemonToAPICommunicationError("Daemon closed the connection", 10053)
            elif e.errno == 10054:
                raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Did you close it?", 10054)
            elif e.errno == 10061:
                raise YOREDaemonToAPICommunicationError("Daemon could not be reach - Did you run run_daemon()?", 10061)
            else:
                raise
        except Exception:
            raise
