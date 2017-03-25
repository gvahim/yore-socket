"""
Author: YochaiE
Date: 09.02.2016

Description:
The YORE Daemon with a capital D!
This is the actual brain of everything. While the resocket interface is only a nice shell/API, this
script does all the work. It's fairly complicated so take a lot of time to read through it and understand everything.
A lot of multithreading is in place, so take the time to first understand the protocol and the control flow, and
then jump into the code.

The daemon communicates with CLIENTS - python scripts that use the RESOCKET class. Every client can
perform various commands that end up being processed here. This script translates every resocket command
to a protocol packet/packets, and keeps track of the state. You can think of it as a network driver written in python.

NOTES & TODO:

    Scapy's haslayer does not check the level of the layer. This might lead to weird encapsulation attacks.
    (Which might be good)
    The IPC and state checking is not infallible. We assume no jitter or attempt to hack the daemon, but that is not
        necessarily the case. Maybe we need to harden the IPC layer a little more.
"""

# Imports. What can I say.
import os
import select
import socket
import struct
import threading
from time import sleep

from scapy.all import Raw, send, sniff, conf, srp1, Ether, get_if_hwaddr, ETHER_BROADCAST
from scapy.all import YO, RE, YOARP, register_yoip

import protocol_errors
from socketclient import SocketClient
from constants import CLIENT_STATE, FLAG, OPCODE, TIMEOUT_CHECK
from ..constants import SOCK_RAW, SOCK_RE, RESOCKET_DAEMON_HOST, RESOCKET_DAEMON_DEFAULT_PORT, SERIALIZER_CMD, \
    NON_BLOCKING, BLOCKING
from .. import serializer
from ..YOREException import YOREException


# The essence of this file and protocol. This is the monstrous class that's the brains of the
# YORE package. If you wish to understand it from the beginning, start from the "run" command which is
# way down.


class ProtocolDaemon(object):

    def __init__(self, daemon_port=None):
        """
        Initializer function.
         :param daemon_port: The daemon localhost TCP Port. Use only if you use multiple YORE Daemons on the same
         computer (if you want to have multiple YO addresses on the same computer).
        """
        self.daemon_port = daemon_port if daemon_port is not None else RESOCKET_DAEMON_DEFAULT_PORT

        # Serializer for IPC calls
        self.serializer = serializer.Serializer()

        # YO address is nothing at this stage.
        self.yo_addr = None

        # Client list and a helper lock to synchronize the threads.
        self.client_list = []
        self.client_list_lock = threading.RLock()

        # Client debug id counter
        self.debug_id = 1

        # create threads
        self.clientsThread = None
        self.sniffThread = None
        self.verbose_level = 1

        try:
            iface, a, gw = conf.route.route("0.0.0.0")
            src_mac = get_if_hwaddr(iface)
        except:
            iface, a, gw = conf.route.route("8.8.8.8")
            src_mac = get_if_hwaddr(iface)
        self.iface = iface
        self.src_mac = src_mac
        self.L2socket = conf.L2socket(iface=self.iface)

        self.filter_src_addresses = None
        self.send_error_port_not_open = True

    def set_filter_address(self, addresses):
        """
        Set a daemon filter for addresses to get packets from
        :param addresses: None - for no filter, 'X.Y' for single address or list of addresses
        """
        if isinstance(addresses, basestring):
            addresses = [addresses]
        self.filter_src_addresses = addresses

    def set_verbose_level(self, level):
        self.verbose_level = level

    def prints(self, string, verbose_level=1):
        if self.verbose_level <= verbose_level:
            print string

    # Send an IPC call through a select socket.
    # Since we usually return a certain result from the ProtocolDaemon, the send IPC
    # function format here is made of "result, cmd, args." The cmd is simply
    # the first argument in the argument list. This is used to verify in the front end
    # that it got an answer for the action it was doing, and not something else.
    def send_ipc(self, sock, result, cmd, args):
        # insert cmd as the first arg.
        larges = list(args)
        larges.insert(0, cmd)

        # Serialize and send away!
        data = self.serializer.serialize(result, larges)
        try:
            sock.send(data)
        except:
            self.prints( "Warning! This is a bad socket, should be removed on select.")

    # The main running function for the ProtocolDaemon. It fires up two important threads -
    # one for sniffing packets, the other waiting for client connections (IPC).
    def run(self):
        print '^^^^'
        # Verify that we actually do have a YO address before running.
        if self.yo_addr is not None:
            self.prints( "Starting internal threads")
            # Start a sniffing thread - use scapy's sniff function.
            # Use internal_filter as the packet filter, and internal_sniff as the actual sniff processing.
            self.sniffThread = threading.Thread(target=sniff,
                                                kwargs=dict(prn=self.internal_sniff, lfilter=self.internal_filter))
            self.sniffThread.setDaemon(True)
            self.sniffThread.start()

            # Start the clients thread. This receives new Resocket connections from all over the system.
            self.clientsThread = threading.Thread(target=self.handle_clients)
            self.clientsThread.setDaemon(True)
            self.clientsThread.start()
        else:
            raise YOREException("Error! Must set a YO address before running the ProtocolDaemon!")
        print '***'

    # The main thread that accepts and handles clients data.
    def handle_clients(self):
        # Initialize IPC Socket and start listening for new client.
        host = RESOCKET_DAEMON_HOST
        port = self.daemon_port
        backlog = 5
        size = 1024
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(backlog)
        self.prints( "Initialized a YORE ProtocolDaemon on HOST %s PORT %s" % (host, port), 4)

        # Input_streams represents all the ProtocolDaemon's sockets. Both it's listening socket, and
        # all the client. We start with the server socket only and add sockets as we accept them.
        input_streams = [server]
        running = 1

        # It would be nice to add a break capability on Ctrl-C or something.
        while running:

            # Select the sockets that has input and go over them.
            try:
                input_ready, output_ready, except_ready = select.select(input_streams, [], [])
            except socket.error as e:
                self.prints( "warning - corrupted socket!", 4)
                if e.errno != 9:
                    raise
                clients = list(self.client_list)
                for client in clients:
                    s = client.socket
                    if s in input_streams:
                        try:
                            select.select([s], [], [])
                        except:
                            self.prints( "client closed connection (%d, %s)" % (client.debug_id, client.src_addr[0]), 4)
                            self.handle_client_close(client)
                            input_streams.remove(s)
                            self.client_list.remove(client)
                remaining_input_streams = list(input_streams)
                for s in remaining_input_streams:
                    try:
                        select.select([s], [], [])
                    except:
                        self.prints( "removed unknown input stream", 4)
                        input_streams.remove(s)
                input_ready, output_ready, except_ready = select.select(input_streams, [], [])

            for s in input_ready:
                # If we have input on the server socket, we probably have a new Resocket (client) popping up.
                # Accept it and add it to the socket list.
                if s == server:
                    client_socket, address = server.accept()
                    self.prints( "Got a new client from %s ClientID %d" % (address[0], self.debug_id), 3)
                    input_streams.append(client_socket)

                    # Lock the client list lock and only then edit the list. We work in a
                    # multi-thread environment, we don't want anything fishy to happen.
                    # Pair the new accepted socket with a new client object.
                    with self.client_list_lock:
                        new_client = SocketClient(client_socket)
                        new_client.protocol = SOCK_RE
                        new_client.src_addr = address
                        new_client.debug_id = self.debug_id
                        self.debug_id += 1
                        self.client_list.append(new_client)

                else:
                    # If it's not the server socket, it's a client socket, meaning
                    # we got an IPC call.
                    try:
                        data = s.recv(size)
                    except:
                        data = None

                    # If there's data on the line, we got an IPC call
                    if data:
                        # Make sure we are able to match the receiving socket to a client.
                        unknown = True
                        with self.client_list_lock:
                            for client in self.client_list:
                                # This is a little hacky - since we go over the list anyway, see if
                                # there are any sockets we need to get rid of (closed connections).
                                # If there are - remove them from the list.
                                if client.removable:
                                    self.client_list.remove(client)

                                # Check if the socket matches a client socket (this actually works in python!
                                # it compares an instance!)
                                if client.socket == s:
                                    # Add the received data to the client's IPC buffer
                                    client.ipc_recv_buffer += data
                                    if len(client.ipc_recv_buffer) >= 8:
                                        # If the buffer has the header, see how much data is expected and wait for it.
                                        data_length = struct.unpack("<I", client.ipc_recv_buffer[4:8])[0]
                                        if len(client.ipc_recv_buffer) >= data_length - 8:
                                            # If we acquired all the data for the IPC call, we deserialize it and
                                            # pass it into the client IPC handling function.
                                            ipc_data = client.ipc_recv_buffer[0:data_length + 8]
                                            client.ipc_recv_buffer = client.ipc_recv_buffer[data_length + 8:]
                                            cmd, args = self.serializer.deserialize(ipc_data)
                                            self.handle_client_input(client, cmd, args)

                                    # If a client was matched this socket is not unknown.
                                    unknown = False

                        # If no matching client is found, we don't know who this socket or data is for.
                        # Get rid of it.
                        if unknown:
                            self.prints( "Got input from unknown socket, closing it", 3)
                            s.close()


                    # TODO: check if this right ?
                    # If there's no data - a client has closed it's connection (a Resocket has closed or died)
                    # so we want to get rid of it. Try to close the Resocket gracefully (FIN flag).
                    else:
                        clients = list(self.client_list)
                        for client in clients:
                            #client.blocking == BLOCKING and
                            if client.protocol == SOCK_RE and client.socket == s:
                                self.prints( "A client closed it's connection (%d, %s)" % (client.debug_id, client.src_addr[0]), 3)
                                self.handle_client_close(client)
                                self.client_list.remove(client)
                                break
                        # s.close()
                        input_streams.remove(s)
        # Right...
        server.close()

    # This function is simply a switch-case for handling a command from a client.
    # It receives the client, command, and an optional list of arguments.
    # Each command gets its own set of arguments
    def handle_client_input(self, client, cmd, args):
        self.prints( "Handling client %s ID=%d %d %s" % (client.src_addr[0], client.debug_id, cmd, repr(args)),3)

        with self.client_list_lock:
            if cmd == SERIALIZER_CMD.BIND:
                self.handle_client_bind(client, args[0], args[1])
            elif cmd == SERIALIZER_CMD.LISTEN:
                self.handle_client_listen(client, args[0])
            elif cmd == SERIALIZER_CMD.ACCEPT:
                self.handle_client_accept(client)
            elif cmd == SERIALIZER_CMD.CONNECT:
                self.handle_client_connect(client, args[0], args[1])
            elif cmd == SERIALIZER_CMD.SEND:
                self.handle_client_send(client, args[0])
            elif cmd == SERIALIZER_CMD.RECV:
                self.handle_client_recv(client, args[0])
            elif cmd == SERIALIZER_CMD.CLOSE:
                self.handle_client_close(client)
            elif cmd == SERIALIZER_CMD.EXIST:
                self.handle_client_accepted(client, args[0], args[1], args[2], args[3], args[4])
            elif cmd == SERIALIZER_CMD.SET_PROTOCOL:
                self.handle_client_set_protocol(client, args[0])
            elif cmd == SERIALIZER_CMD.SET_BLOCKING:
                self.handle_client_set_blocking(client, args[0])
            elif cmd == SERIALIZER_CMD.SET_TIMEOUT:
                self.handle_client_set_timeout(client, args[0])
            elif cmd == SERIALIZER_CMD.SENDTO:
                self.handle_client_sendto(client, args[0], args[1])
            elif cmd == SERIALIZER_CMD.RECVFROM:
                self.handle_client_recvfrom(client, args[0])
            elif cmd == SERIALIZER_CMD.GET_SID:
                self.handle_client_get_sid(client)
            elif cmd == SERIALIZER_CMD.ADD_TO_ACK_COUNTER:
                self.handle_client_add_to_ack_counter(client, args[0])
            elif cmd == SERIALIZER_CMD.ADD_TO_SEQ_COUNTER:
                self.handle_client_add_to_seq_counter(client, args[0])
            elif cmd == SERIALIZER_CMD.EMPTY:
                self.handle_empty_ipc(client)
            else:
                self.prints( "Unknown command %s, ignoring" % cmd)

    # Filter YO and ARP (YOARP) packets. Everything else - to the dumpster!
    # Notice that we use haslayer. Encapsulation or layer manipulation may pose a problem here.
    # If it does, we'd like to intentionally treat this as an implementation bug.
    @staticmethod
    def internal_filter(pkt):
        if pkt.haslayer("YO") or pkt.haslayer("YOARP"):
            return True

        return False

    # Handle a client that's accepted (EXIST, born out of accept command)
    def handle_client_accepted(self, client, dest, sid, last_packet, blocking, timeout):
        # Initiate a new session for the client - it was just born.
        with self.client_list_lock:
            # accept_params = (self._convert_yoip_to_num(self.yo_addr), self._convert_yoip_to_num(pkt[YO].src),
            # client.listen_port, pkt[RE].sid, str(response))
            client.initiate_session(None, 0)

        # A little counter-intuitive but the session id is GENERATED, since this is a SERVER
        # socket. Meaning, in it's point of view, it was the one who decided on the SID.
        # This is useful for our filtering and candidate selecting. 
        client.sid_generated = sid
        client.yo_dest = dest
        client.blocking = blocking
        client.timeout = timeout

        # Set the last packet to be the one that our "father" socket sent.
        # Again, we don't want to get duplicates here and cancel the session for no reason.
        client.add_last_packet(last_packet, lock=True)
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.EXIST, ["EXIST"])

    # Handle a client BIND command.
    # This function receives a client, a host (YO address) and a destination port to bind to.
    def handle_client_bind(self, client, host, port):
        if client.protocol != SOCK_RE and client.protocol != SOCK_RAW:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.BIND,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # Convert the YO Address to a numeric form
        yo_addr = self._convert_yoip_to_num(self.yo_addr)

        # Make sure we bind the socket for the address we actually own. Otherwise, send
        # an error.
        if host != yo_addr:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.BIND, ["INVALID_YOIP"])
            return

        if client.protocol == SOCK_RE:
            # Make sure no other socket is already bound to the port we're trying to bind.
            # Otherwise, return an error.
            with self.client_list_lock:
                for other_client in self.client_list:
                    if other_client.listen_port == port:
                        self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.BIND,
                                      ["BIND_PORT_ALREADY_IN_USE"])
                        return

                client.listen_port = port
                self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.BIND, ["BIND"])
        elif client.protocol == SOCK_RAW:
            client.listen_port = -2
            self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.BIND, ["BIND"])

    # We knowingly ignore the backlog. Sue us. But seriously, doesn't serve a lot of
    # purpose so we don't implement it.
    def handle_client_listen(self, client, backlog):
        if client.protocol != SOCK_RE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.LISTEN,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # We're not verifying the state here, should do it, even though the front end should take care of it.
        client.socket_state = CLIENT_STATE.LISTEN
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.LISTEN, ["LISTEN"])

    # Handles client accept commands
    def handle_client_accept(self, client):
        if client.protocol != SOCK_RE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.ACCEPT,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # This just changes the state from listen to initiating connection. 
        if client.socket_state in (CLIENT_STATE.LISTEN, CLIENT_STATE.INITIATING_CONNECTION):
            client.socket_state = CLIENT_STATE.INITIATING_CONNECTION
        else:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.ACCEPT,
                          ["ACCEPT_MUST_BE_IN_LISTEN_STATE"])

    # Handle a client CONNECT command.
    # Requires a client, dest host and dest port.
    def handle_client_connect(self, client, host, port):
        if client.protocol != SOCK_RE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.CONNECT,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # Do a sanity check for the socket state.
        if client.socket_state != CLIENT_STATE.NONE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.CONNECT,
                          ["CONNECT_MUST_BE_IN_NONE_STATE"])
        else:

            # The port must be a valid WORD value.
            if port < 1 or port > 65535:
                self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.CONNECT,
                              ["PORT_MUST_BE_BETWEEN_1_TO_65535"])
                return

            # Set the client params
            client.yo_dest = host
            client.dest_port = port

            client.socket_state = CLIENT_STATE.INITIATING_CONNECTION
            client.waiting_for_response = 1

            # Genertate an initial sequence number
            new_seq = 0
            while new_seq == 0:
                new_seq = ord(os.urandom(1)[0])
            client.initial_seq = new_seq

            # Send a RE SYN packet (Connection initiation)
            connect_syn_packet = YO(src=self.yo_addr, dst=client.yo_dest, opcode="RE") / RE(sid=0, flags="S",
                                                                                            seq=client.initial_seq,
                                                                                            ack=0) / Raw(
                load=struct.pack("<H", client.dest_port) + "Connection Initiation")
            self.new_send(connect_syn_packet, client=client, expect_ack=True)

    # Set a new client protocol type
    def handle_client_set_protocol(self, client, protocol):
        client.protocol = protocol
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.SET_PROTOCOL, ["SET_PROTOCOL"])

    def handle_empty_ipc(self, client):
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.EMPTY, ["EMPTY"])

    def handle_client_set_blocking(self, client, blocking):
        client.blocking = blocking
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.SET_BLOCKING, ["SET_BLOCKING"])

    def handle_client_set_timeout(self, client, timeout):
        client.timeout = timeout
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.SET_TIMEOUT, ["SET_TIMEOUT"])

    def handle_client_add_to_ack_counter(self, client, number):
        client.ack = (client.ack + number) % 256
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.ADD_TO_ACK_COUNTER, ["ADD_TO_ACK_COUNTER"])

    def handle_client_add_to_seq_counter(self, client, number):
        client.seq = (client.seq + number) % 256
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.ADD_TO_SEQ_COUNTER, ["ADD_TO_SEQ_COUNTER"])

    def handle_client_get_sid(self, client):
        sid = client.sid_generated
        if sid == -1:
            sid = client.sid_received
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.GET_SID, [sid])

    # Handle a client SENDTO command
    # The function takes the client and data as an argument
    def handle_client_sendto(self, client, yo_dest, data):
        if client.protocol != SOCK_RAW:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.SENDTO,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # skip the bind check - no real need to check if we were bounded or not.
        if len(data) > 65535 - 13:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.SENDTO,
                          ["SEND_SIZE_IS_TO_LONG"])
            return

        data_packet = YO(src=self.yo_addr, dst=yo_dest, opcode="raw") / Raw(load=data)
        self.new_send(data_packet, client=client, expect_ack=False)
        # Send is a non-blocking command so we signal the client a success on the send command.
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.SENDTO, ["SENDTO"])

    # Handle a client SEND command
    # The function takes the client and data as an argument
    def handle_client_send(self, client, data):
        if client.protocol != SOCK_RE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.SEND,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # Sanity check the state - we can only send data on an established session
        if client.socket_state != CLIENT_STATE.SESSION_ACTIVATED:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.SEND,
                          ["SEND_MUST_BE_IN_ACTIVATED_SESSION"])
        else:

            # Since we might piggyback data on an existing ACK, we can't necessarily send the data right away.
            # We use an incoming and outgoing data locks in order not to mess things up (seq/ack wise).
            # This way (locking) we will not send 2 packets in a row with different meaning.
            with client.outgoing_data_lock:
                with client.incoming_data_lock:

                    # If the user wishes to send more data than 64 bytes, cut the data and insert
                    # the rest for the outgoing data buffer. This buffer is being "chewed" after
                    # every ack. Remember - we don't keep a window so every packet requires an ACK.
                    if len(data) > 64:
                        client.outgoing_data += data[64:]
                        data = data[:64]

                    # Calculate the new sequence number
                    client.seq += len(data)
                    if client.seq > 255:
                        client.seq -= 256

                    # We assume only one of them is used. This is not the best practice, but 
                    # it works.
                    sid = client.sid_generated
                    if sid == -1:
                        sid = client.sid_received

                    # Send the data packet, ACK flag on. Expect an ACK in return.
                    data_packet = YO(src=self.yo_addr, dst=client.yo_dest, opcode="RE") / RE(sid=sid, flags="A",
                                                                                             seq=client.seq,
                                                                                             ack=client.ack) / Raw(
                        load=data)
                    self.new_send(data_packet, client=client, expect_ack=True)

        # Send is a non-blocking command so we signal the client a success on the send command, not necessarily
        # knowing that the data has been received. Again, this mimicks real sockets, but maybe we'd like to change
        # this implementation one day.
        self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.SEND, ["SEND"])


    # Handle a client RECV command.
    # Requires a client and a max bufsize
    def handle_client_recv(self, client, bufsize):
        if client.protocol != SOCK_RE:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.RECV,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        # Simple sanity check on the socket state. We can only receive data while in a session.
        if client.socket_state != CLIENT_STATE.SESSION_ACTIVATED:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.RECV,
                          ["RECV_MUST_BE_IN_ACTIVATED_SESSION"])
            return

        # lock the incoming data buffer
        with client.incoming_data_lock:
            if client.incoming_data != "":

                # If there's more data waiting than the specified bufsize, return only bufsize
                # bytes back to the user. Otherwise, return all the data that's waiting.
                # Remove the data that's been waiting on the socket from the incoming buffer
                if len(client.incoming_data) > bufsize:
                    data = client.incoming_data[:bufsize]
                    client.incoming_data = client.incoming_data[bufsize:]
                else:
                    data = client.incoming_data
                    client.incoming_data = ""

                # Send the received data back to the user. This returns the blocking function "immediately"
                self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECV, [data])
                client.waiting_for_response = 0

            else:
                # If there's no data on the receive buffer, we shall wait (recv) is a blocking function.
                client.waiting_for_response = bufsize

                if client.blocking == NON_BLOCKING:
                    self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECV_EMPTY, [True])
                else:
                    thread = threading.Thread(target=self.wait_for_recv_response, args = (client, ))
                    thread.start()


    def wait_for_recv_response(self, client):
        """
        Wait and check if received response until timeout arrived
        If got none - sends SERIALIZER_CMD.RECV_EMPTY IPC
        :param client:
        """
        for i in range(int(client.timeout/TIMEOUT_CHECK)-1):
            sleep(TIMEOUT_CHECK)
            with client.incoming_data_lock:
                if client.waiting_for_response == 0:
                    return
        sleep(TIMEOUT_CHECK)
        with client.incoming_data_lock:
            if client.waiting_for_response != 0:
                client.waiting_for_response = 0
                self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECV_EMPTY, [True])

    # Handle a client RECVFROM command.
    # Requires a client and a max bufsize
    def handle_client_recvfrom(self, client, bufsize):
        if client.protocol != SOCK_RAW:
            self.send_ipc(client.socket, self.serializer.RESULT_ERROR, SERIALIZER_CMD.RECVFROM,
                          ["UNSUPPORTED_PROTOCOL"])
            return

        with client.incoming_data_lock:
            if len(client.incoming_data_with_address) > 0:
                address, incoming_data = client.incoming_data_with_address[0]
                # If there's more data waiting than the specified bufsize, return only bufsize
                # bytes back to the user. Otherwise, return all the data that's waiting.
                # Remove the data that's been waiting on the socket from the incoming buffer
                if len(incoming_data) > bufsize:
                    data = incoming_data[:bufsize]
                    client.incoming_data_with_address[0] = (address, incoming_data[bufsize:])
                else:
                    data = incoming_data
                    client.incoming_data_with_address.pop(0)

                # Send the received data back to the user. This returns the blocking function "immediately"
                self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECVFROM,
                              [address, data])
                client.waiting_for_response = 0

            else:
                # If there's no data on the receive buffer, we shall wait (recv) is a blocking function.
                client.waiting_for_response = bufsize
                if client.blocking == NON_BLOCKING:
                    self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECV_EMPTY, [True])
                else:
                    thread = threading.Thread(target=self.wait_for_recv_response, args = (client, ))
                    thread.start()


    # Handle a client CLOSE command.
    # Just needs a client. Notice that we also call this function if an IPC connection
    # has closed, and not necessarily if the client chose to close the connection. If an IPC channel
    # has closed, the client is no longer relevant, and we do our best effort to FIN-ACK the other side
    # (if it existed)
    def handle_client_close(self, client):

        # Already explained this
        sid = client.sid_generated
        if sid == -1:
            sid = client.sid_received

        # if sid == -1:
        #    self.__send_ipc(client.socket, self.Serializer.RESULT_ERROR, SERIALIZER_CMD.CLOSE, ["NO_DEFINED_SID"])
        #    return

        # Lock the data locks, since our FIN-ACK packet has to be precise (seq/ack).
        with client.outgoing_data_lock:
            with client.incoming_data_lock:
                if sid == -1:
                    sid = client.fin_sid
                self.initiate_close_client_procedure(client, sid)

    # This function checks if the socket is in an activated session and if it is,
    # it sends a FIN ACK, waiting for a FIN in return (without an ACK!)
    def initiate_close_client_procedure(self, client, sid):
        if client.socket_state == CLIENT_STATE.SESSION_ACTIVATED:

            if client.fin_seq == -1:
                client.fin_seq = client.seq
            if client.fin_ack == -1:
                client.fin_ack = client.ack

            fin_ack_packet = YO(src=self.yo_addr, dst=client.yo_dest, opcode="RE") / RE(sid=sid, flags="FA",
                                                                                        seq=client.fin_seq,
                                                                                        ack=client.fin_ack)
            # This might have sync issues, think about this.
            client.socket_state = CLIENT_STATE.WAITING_FIN
            self.new_send(fin_ack_packet, client=client, expect_ack=False)


    def handle_re_session_packet(self, pkt):
        """

        :param pkt: pkt
        """
        # Lock the client list.
        with self.client_list_lock:
            # Generate a list of potential clients that can have this packet. This is mostly for debugging
            # purposes. We always want the packet to match to exactly one client - no more, no less.
            # If this packet doesn't belong to any session, drop it with an error (This can help session mapping).
            # If it belongs to one client, let the client handle the packet according to its state.
            # if the packet belongs to more than one client - something bad must've happend. This situation should not
            # happen, and we need to debug these cases. It's extra tricky when dealing with a localhost server/client.
            potential_clients = []

            # Go over the clients, see which one has the matching session id.
            for client in self.client_list:
                # Check that this is RE client
                # Also, make sure the packet's source YO address matches the one that's configured for
                # The client. The SID, PLUS the YO ADDRESS make up for the tcp/ip equivalent of a 4 tuple.
                # And also -
                # See if the packet's SID matches a client's GENERATED SID. A generated SID means
                # this is a server socket, because the server initially generates a SID after a SYN.
                # OR
                # See if the packet's SID matches a client's RECEIVED SID. A received SID means
                # this is a client socket, because a client receives it's SID from a server in a SYN ACK.

                if client.protocol != SOCK_RE or self._convert_yoip_to_num(pkt[YO].src) != client.yo_dest or \
                                pkt[RE].sid not in (client.sid_generated, client.sid_received):
                    continue
                with client.last_packet_lock:
                    # If the client has a last sent packet, verify it does not match
                    # the one we just received (think about loopback interface, we sniff what we send)

                    # If there's no match between the last sent packet and the one just received, we
                    # add this client as an potential candidate to receive this packet.
                    if not client.in_last_packet(pkt, lock=False):
                        potential_clients.append(client)
                        # I kept this log line since it can really help understanding which client is being picked
                        # as a candidate and for what packet. Uncomment it if you'd like to know.
                        """
                        print '\n\t'.join(["DEBUG Potential client:",
                                           "GENERATED/RECEIVED",
                                           "Client ID: %d" % client.debug_id,
                                           "Last Packet: %s" % str(client.last_packet).encode("hex"),
                                           "Current Packet: %s" % str(pkt.payload).encode("hex"),
                                           "Match: %s" % str(str(pkt.payload) == str(client.last_packet)),
                                           "Flags: %d" % pkt[RE].flags,
                                           "SID: %d" % pkt[RE].sid])
                        """

            # After the loop over the client has finished, count the potential clients we generated.
            # If no client is a potential, someone sent us a fishy packet. Kindly respond with an error.
            if len(potential_clients) == 0:
                if pkt[RE].flags & FLAG.ERR != 0:
                    self.general_error(protocol_errors.SID_DOES_NOT_EXIST, None, pkt, 1)

            # If the packet matches exactly one client (which is the good scenario), handle
            # this client's packet.
            elif len(potential_clients) == 1:
                # I kept this print to help understanding which client was chosen to handle a packet.
                # Uncomment it if you want.
                #print "DEBUG chose client %d " % potential_clients[0].debug_id
                self.handle_re_session_client_packet(pkt, potential_clients[0])

            # If more than one potential client was found there's a weird bug that needs to
            # be found.
            else:
                self.prints( "Potential clients %d" % len(potential_clients))
                print '~'
                pkt.show()
                print '~'
                for c in potential_clients:
                    print '*'
                    for i in c.last_packet:
                        print len(i), i
                    print '*'

                raise YOREException("DEBUG This is a weird scenario")

    def handle_raw_packet(self, pkt):
        """

        :param pkt: pkt
        """
        # Lock the client list.
        with self.client_list_lock:
            potential_clients = []
            # Go over the clients, see which one has the matching session id.
            for client in self.client_list:
                # Verify that the dest address is ours
                if client.protocol != SOCK_RAW or pkt[YO].dst != self.yo_addr:
                    continue
                with client.last_packet_lock:
                    # If the client has a last sent packet, verify it does not match
                    if not client.in_last_packet(pkt, lock=False):
                        potential_clients.append(client)
                    #else:
                    #    client.last_packet = None

            # If no client is a potential, someone sent us a fishy packet. ignore.
            for client in potential_clients:
                self.handle_raw_client_packet(pkt, client)

    def internal_sniff(self, pkt):
        """
        The internal sniff function. This function is invoked when a packet that has passed the filters has arrived.
        From this point we need to route the packet to a handler function. We determine which function by the packet's
        type and flags.
        :param pkt: pkt
        """
        # The ProtocolDaemon registers the YO IP and so it also has to answer any ARP request
        # directed at its way.
        # Notice that we check for layer YOARP, and not ARP. YOARP is a custom ARP packet
        # since scapy's ARP does not support variable length fields very well, unlike the ARP
        # protocol.
        if pkt.haslayer("YOARP"):
            self.handle_arp_packet(pkt)

        elif pkt.haslayer("YO") and pkt[YO].dst == self.yo_addr and \
                (self.filter_src_addresses is None or pkt[YO].src in self.filter_src_addresses):

            if pkt[YO].opcode == OPCODE.PING :
                # Answer pings directed at our YOIP with pong
                pong_packet = YO(opcode="pong", dst=pkt[YO].src, src=self.yo_addr) / Raw(load="Pong")
                self.new_send(pong_packet)

            elif pkt[YO].opcode == OPCODE.RE and pkt.haslayer("RE"):
                # Handle any RE packet
                # If the packet's session id is 0 - treat it as initial session packet.
                # Otherwise, this packet probably belongs to an existing session. Verify which client is supposed to
                # receive this packet and handle it.
                if pkt[RE].sid == 0:
                    self.handle_re_initial_packet(pkt)
                else:
                    self.handle_re_session_packet(pkt)

            elif pkt[YO].opcode == OPCODE.RAW and pkt.haslayer("Raw"):
                # Handle any YO RAW packet
                self.handle_raw_packet(pkt)


    # The "new" send function is a hub for most of the sends in the ProtocolDaemon.
    # We use if for multiple purposes:
    #    Specifying a client, if any, to associate it with its last sent packet. This is
    #         relevant for identifying loopback packets
    #    Expecting an ack in return - If we do expect an ack for the sent packt a new thread
    #         is born which tries to send the packet
    #    Cancel scapy's verbosity. Seriously, this is a pain!
    def new_send(self, pkt, client=None, expect_ack=False):
        # Set the last packet for a client if we have one.
        if client:
            client.add_last_packet(pkt, lock=True)

        # If we do not expect an ack, send the packet and that's it. Otherwise,
        # fire up a thread that implements ARQ.
        if not expect_ack:
            send(pkt, verbose=0)
        else:
            arq_thread = threading.Thread(target=self.arq_thread, args=[client, pkt])
            arq_thread.start()

    # The ARQ thread function. Receives a client and a packet to retry.
    # This function tries to send a packet, and then sleeps for a given interval.
    # It waits on an event to wake up. If the event was woken up before the waiting period has
    # finished, it means that we received an ack. Otherwise, it tries to sends again and sleep
    # in an exponential backoff manner.
    @staticmethod
    def arq_thread(client, pkt):
        # TODO: CANCEL THOSE LINES - this will cancel the retransmit
        # send(pkt, verbose=0)
        # return

        expected_ack = pkt[RE].seq
        # Keep original socket state. This helps us identify when we wake up from an ACK.
        orig_socket_state = client.socket_state

        # The backoff intervals we're using
        wait_intervals = [2, 4, 6]

        # We clear the event we're about to wait upon.
        client.acknowledge_received_events[expected_ack] = threading.Event()
        event = client.acknowledge_received_events[expected_ack]
        event.clear()

        # I kept this packet_loss clause because it's a neat code to simulate
        # packet_loss and see how ARQ and the ProtocolDaemon behaves. Obviously, it's neutered, but you can
        # bring back the randrange function to make the effect of packet loss.
        packet_loss = 1  # random.randrange(0,10)
        if packet_loss < 8:
            send(pkt, verbose=0)

        # Wait for a given interval
        for interval_index in range(len(wait_intervals)):
            interval = wait_intervals[interval_index]
            # Wait for the event to be set, or timeout. A timeout yields False, a set event
            # yields true.
            wait_result = event.wait(interval)
            if wait_result:
                # We got the ACK we wanted, safely return.
                event.clear()
                if expected_ack in client.acknowledge_received_events:
                    client.acknowledge_received_events.pop(expected_ack)
                return
            else:
                # If we woke up from a timeout and the socket state is still the same when we began the ARQ,
                # send another packet.
                if orig_socket_state == client.socket_state:
                    # Packet-loss can happen here to, If you'd like it to.
                    packet_loss = 1  # random.randrange(0,10)
                    if packet_loss < 8:
                        if YO in pkt:
                            print "\nRetransmitting (%d) from %s" % (interval_index+1, pkt[YO].src)
                        elif YOARP in pkt:
                            print "\nRetransmitting (%d) from %s" % (interval_index+1, pkt[YOARP].psrc)
                        else:
                            print "\nRetransmitting (%d) from ?" % (interval_index+1)

                        client.add_last_packet(pkt, lock=True)
                        send(pkt, verbose=0)
                else:
                    event.clear()
                    if expected_ack in client.acknowledge_received_events:
                        client.acknowledge_received_events.pop(expected_ack)
                    return

        # If the client socket state is None after the backoff, this socket is closed, so we simply finish
        # the ARQ thread
        if client.socket_state == CLIENT_STATE.NONE:
            return

        # If the client is waiting for FIN, just finish the session without an error. Otherwise,
        # send an error that the ACK was not received for a packet.
        if client.socket_state != CLIENT_STATE.WAITING_FIN:
            client.finish_session(error=protocol_errors.ACK_TIMEOUT)
        else:
            client.finish_session()

    # This function handles packets that are not associated with any session - thus, initial packets.
    # They are actually relevant for session 0 which is a "bootstrap" session.
    # We decide how to handle the packet by its flags.
    def handle_re_initial_packet(self, pkt):
        # Handle packet with a SYN only flag.
        if pkt[RE].flags == FLAG.SYN:
            # Notice we don't check SEQ or ACK here since it's a recommendation only by the RFC.
            # A Connection SYN must have a dest port specified  (2 bytes)
            # Otherwise, this packet is no good - send an error.
            if len(pkt[Raw].load) < 2:
                self.general_error(protocol_errors.SYN_0_NO_DEST_PORT, None, pkt, 1)
            else:
                # Go over the client list, see if anyone already listens on this port and
                # is in the correct socket state.
                with self.client_list_lock:
                    for client in self.client_list:
                        # Make sure the socket is in INITIATING CONNECTION state (which is listen)
                        if client.socket_state == CLIENT_STATE.INITIATING_CONNECTION:
                            # Compare the packet's dest port to to client's listen_port (there should be only one!).
                            if client.listen_port == struct.unpack("<H", pkt[Raw].load[0:2])[0]:

                                # Verify that we're not using a SID that's already in use.
                                # Generate a random SID, see it doesn't match any other SID that
                                # has the same dest address. If it does, loop. This can actually
                                # cause a DoS if now session is open. 
                                new_sid_valid = False
                                new_sid = None
                                while not new_sid_valid:
                                    new_sid = struct.unpack("<H", os.urandom(2))[0]
                                    new_sid_valid = True
                                    for client_sid in self.client_list:
                                        if ((new_sid == client_sid.sid_generated or
                                                     new_sid == client_sid.sid_received) and
                                                (client.yo_dest == pkt[YO].src)):
                                            new_sid_valid = False
                                            break

                                if new_sid is None:
                                    continue

                                # Change the client's socket state to initiating session (which is waiting for)
                                client.socket_state = CLIENT_STATE.INITIATING_SESSION
                                client.sid_generated = new_sid

                                # This is a temporary setting that vanishes when the session is created.
                                # The socket has to know who's its destination for the packet filter to work properly.
                                # We use this to identify which client should have the packet and avoid SID collision
                                client.yo_dest = self._convert_yoip_to_num(pkt[YO].src)

                                # Respond with a SYN-ACK packet. 
                                # Remember the SYN-ACK contains both the generated Session ID,
                                # and the listen port (for identification)
                                response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / \
                                           RE(sid=0, flags="SA", seq=0, ack=pkt[RE].seq) / \
                                           Raw(load=struct.pack("<H", client.sid_generated) +
                                                    struct.pack("<H", client.listen_port))

                                # Wake up the ARQ task and finish it - we got the response we expected.
                                # TODO: should be here?
                                self.got_ack(client, pkt)

                                # Even though we send a SYN-ACK, we expect the next packet - a Session SYN packet. That's
                                # why the ARE flag is True.
                                self.new_send(response, client=client, expect_ack=True)
                                return

                # If no client was matched, respond that the port is not open (allows for port mapping)
                if self.send_error_port_not_open == True:
                    self.general_error(protocol_errors.DEST_PORT_IS_NOT_OPEN, None, pkt, 1)

        # Check if the packet's flags are SYN-ACK
        elif pkt[RE].flags == (FLAG.SYN | FLAG.ACK):
            with self.client_list_lock:
                # Go over the client list, see if someone is expecting this SYN-ACK
                for client in self.client_list:

                    # Make sure the client's initial sequence number matches the packet's acknowledgement number.
                    if client.initial_seq == pkt[RE].ack:

                        # Make sure the packet has at least 4 bytes of data - 2 for Session ID, 2 for listen port.
                        # We ignore any more data (secret communication channel?)
                        if len(pkt[Raw].load) >= 4:
                            # Verify that the client's destination port matches the given packet's listen port
                            if client.dest_port == struct.unpack("<H", pkt[Raw].load[2:4])[0]:

                                # Hurrah! It's a match! Extract the session id and change the client's state.
                                client.sid_received = struct.unpack("<H", pkt[Raw].load[0:2])[0]
                                client.socket_state = CLIENT_STATE.INITIATING_SESSION

                                # Generate a response SYN. This time the SYN is a Session SYN, not an initial SYN.
                                response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / RE(
                                    sid=client.sid_received, flags="S") / Raw(
                                    load=struct.pack("<H", client.sid_received) + struct.pack("<H", client.dest_port))
                                client.initial_seq = -1

                                # Wake up the ARQ task and finish it - we got the response we expected.
                                self.got_ack(client, pkt)

                                # Expect a session SYN for the sent connection SYN-ACK.
                                self.new_send(response, client=client, expect_ack=True)
                                return
                            else:
                                # The seq/ack matches but the dest port does not. This can actually be a problem if 
                                # a connection is being initialized with the same random syn and ack numbers.
                                self.general_error(protocol_errors.DEST_PORT_INIT_SEQ_MISMATCH, client, pkt, 1)
                                return

                        # The packet was matches to a client, but not enough payload bytes were sent,
                        # so we couldn't match it.
                        else:
                            self.general_error(protocol_errors.SYN_ACK_PAYLOAD_TOO_SMALL, client, pkt, 1)
                            return

            # If the SYN-ACK was not aimed at anyone, return an error stating that
            # no connection was opened.
            self.general_error(protocol_errors.DID_NOT_INIT_CONNECTION, None, pkt, 1)

        # There's not a lot we can do with an error in this stage
        # since it's not associated with any session.
        elif pkt[RE].flags & FLAG.ERR != 0:
            pass

        else:
            self.general_error(protocol_errors.ILLEGAL_FLAG_SID_0, None, pkt, 1)

    def got_ack(self, client, pkt):
        if RE in pkt and pkt[RE].flags & FLAG.ACK != 0 and pkt[RE].ack in client.acknowledge_received_events:
            client.acknowledge_received_events[pkt[RE].ack].set()

    # A helper function that converts a textual YO address into a numerical one
    @staticmethod
    def _convert_yoip_to_num(yoip):
        if type(yoip) is str:
            a, b = yoip.split(".")
            return struct.unpack(">H", struct.pack(">BB", int(a), int(b)))[0]
        else:
            return yoip

    @staticmethod
    def _convert_num_to_yoip(num):
        a, b = struct.unpack(">BB", struct.pack(">H", num))
        return str(a) + '.' + str(b)

    # This function handles all the packets that are raw packets without RE
    def handle_raw_client_packet(self, pkt, client):
        # Lock the incoming data lock
        with client.incoming_data_lock:

            # Add the data received to the incoming data buffer. 
            # Since we don't know if the user is on a "recv" right now or what's
            # his buffer size, we keep the data until a recv is called.
            data_len = pkt[YO].len
            client.incoming_data_with_address.append((pkt[YO].src, pkt[Raw].load[:data_len]))

            # If a recv is pending, check the buf size and send as
            # much data of the buffer as possible.
            if client.blocking == BLOCKING and client.waiting_for_response > 0:
                buffer_size = client.waiting_for_response
                address, incoming_data = client.incoming_data_with_address[0]

                if len(incoming_data) > buffer_size:
                    data = incoming_data[:buffer_size]
                    client.incoming_data_with_address[0] = (address, incoming_data[buffer_size:])
                else:
                    data = incoming_data
                    client.incoming_data_with_address.pop(0)

                # Send the received data over the IPC.
                self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS, SERIALIZER_CMD.RECVFROM,
                              [address, data])

                # We went what we possibly could back to the socket.
                # No longer waiting for response.
                client.waiting_for_response = 0

    # This function handles all the packets that are relevant for existing sessions,
    # and not ones that are being initialized.
    # It takes a client and packet as input.
    def handle_re_session_client_packet(self, pkt, client):
        # Handle SYN session packets.
        if pkt[RE].flags == FLAG.SYN:
            # Verify that the client expecting the packet is in the correct state.
            # Also, verify that both seq and ack are 0. Otherwise - return error.
            if client.socket_state == CLIENT_STATE.INITIATING_SESSION:
                if pkt[RE].seq != 0:
                    self.general_error(protocol_errors.INITIAL_SEQ_MUST_BE_0, client, pkt, 1)
                    return
                if pkt[RE].ack != 0:
                    self.general_error(protocol_errors.INITIAL_ACK_MUST_BE_0, client, pkt, 1)
                    return

                # Prepare an adequate response (SYN-ACK)
                response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / RE(sid=client.sid_generated, flags="SA",
                                                                                   seq=0, ack=0)

                # Wake up the ARQ task and finish it - we got the response we expected.
                # TODO: should we have this?
                self.got_ack(client, pkt)

                # Send the SYN-ACK packet, expect an ACK in return
                self.new_send(response, client=client, expect_ack=True)

                return

            # If the client is not in the correct state and is not in FIN state, answer
            # error - syn cannot be sent after session initiation.
            elif client.socket_state != CLIENT_STATE.WAITING_FIN:
                self.general_error(protocol_errors.SYN_IS_ILLEGAL_AFTER_SESSION_INITIATION)
                return

        # Handle SYN ACK session packets
        elif pkt[RE].flags == (FLAG.SYN | FLAG.ACK):
            # Verify that the client is in the correct state and that both the seq
            # and ack number are 0. Otherwise, return an error.
            if client.socket_state == CLIENT_STATE.INITIATING_SESSION:
                if pkt[RE].seq != 0:
                    self.general_error(protocol_errors.INITIAL_SEQ_MUST_BE_0, client, pkt, 1)
                    return
                if pkt[RE].ack != 0:
                    self.general_error(protocol_errors.INITIAL_ACK_MUST_BE_0, client, pkt, 1)
                    return

                # This initializes the client socket session, and returns the blocking 
                # "connect" call.
                client.initiate_session()

                # Respond with a final ACK packet. We do not expect an ack on this one - the session is 
                # set up as far as we're concerned from this client.
                response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / RE(sid=client.sid_received, flags="A",
                                                                                   seq=0, ack=0)

                self.new_send(response, client=client, expect_ack=False)
                return

            # If the client is not in the correct state 
            elif client.socket_state != CLIENT_STATE.WAITING_FIN:
                if pkt[RE].seq != 0 or pkt[RE].ack != 0:
                    return
                if client.seq == 0 and client.ack == 0:
                    # Just ignore - no need to to stop everything
                    # self.general_error(protocol_errors.SYN_ACK_IS_ILLEGAL_AFTER_SESSION_INITIATION, client, pkt, 1)
                    return

        # Handle ACK session packets. This is data, or an ACK response to data.
        elif pkt[RE].flags == FLAG.ACK:

            # This is an ACK received for a SYN-ACK.
            if client.socket_state == CLIENT_STATE.INITIATING_SESSION:

                # Wake up the ARQ task and finish it - we got the response we expected.
                self.got_ack(client, pkt)

                # Create a new baby socket, born out of the server's "accept" command.
                accept_params = (
                    self._convert_yoip_to_num(self.yo_addr), self._convert_yoip_to_num(pkt[YO].src), client.listen_port,
                    pkt[RE].sid, "")

                # This initiates the session in the server context, which actually releases 
                # the socket back to work, and should invoke a new socket for the actual 
                # communication. 
                client.initiate_session(accept_params=accept_params)
                return

            # This can be any ACK received while in session activated mode - 
            # with or without data.
            elif client.socket_state == CLIENT_STATE.SESSION_ACTIVATED:
                # Verify that the acknowledge number is correct
                if pkt[RE].ack == client.seq:

                    # Wake up the ARQ task and finish it - we got the response we expected.
                    # Once we got here we at least got a valid answer, so no point in ARQing 
                    # anymore, even if we don't know exactly what we got.
                    self.got_ack(client, pkt)

                    # If there's no data, don't do anything (we already canceled ARQ thread)
                    if pkt[RE].seq == client.ack:
                        pass
                    else:
                        # If there's data waiting, check how much data has been sent.
                        # Don't forget to modulo 256 (since that's the space we got for seq/ack)
                        if pkt[RE].seq > client.ack:
                            data_len = pkt[RE].seq - client.ack
                        else:
                            data_len = pkt[RE].seq - client.ack + 256

                        # If the data length calculates as bigger than 64 bytes, we have a problem.
                        # Kill the session and report it.
                        if data_len > 64:
                            self.general_error(protocol_errors.DATA_IS_BIGGER_THAN_64_BYTES, client, pkt, 1)
                        else:
                            # Lock the incoming data lock
                            with client.incoming_data_lock:
                                # Add the data received to the incoming data buffer.
                                # Since we don't know if the user is on a "recv" right now or what's
                                # his buffer size, we keep the data until a recv is called.
                                client.incoming_data += pkt[Raw].load[:data_len]

                                # Calculate ack, modulo 256.
                                client.ack += data_len
                                if client.ack > 255:
                                    client.ack -= 256

                                # If a recv is pending, check the buf size and send as 
                                # much data of the buffer as possible.
                                if client.blocking == BLOCKING and client.waiting_for_response > 0:
                                    bufsize = client.waiting_for_response
                                    if len(client.incoming_data) > bufsize:
                                        client_data = client.incoming_data[:bufsize]
                                        client.incoming_data = client.incoming_data[bufsize:]
                                    else:
                                        client_data = client.incoming_data
                                        client.incoming_data = ""

                                    # Send the received data over the IPC.
                                    self.send_ipc(client.socket, self.serializer.RESULT_SUCCESS,
                                                  SERIALIZER_CMD.RECV, [client_data])

                                    # We went what we possibly could back to the socket.
                                    # No longer waiting for response.
                                    client.waiting_for_response = 0

                            # Lock the outgoing data lock
                            with client.outgoing_data_lock:
                                # See if there's more than one packet of data pending. If so, slice
                                # the data and send one packet (after each ACK we get we'll send the other parts)
                                if len(client.outgoing_data) > 64:
                                    data_chunk = client.outgoing_data[:64]
                                    client.outgoing_data = client.outgoing_data[64:]
                                else:
                                    data_chunk = client.outgoing_data
                                    client.outgoing_data = ""

                                # Calculate the new SEQ modulo 256
                                client.seq += len(data_chunk)
                                if client.seq > 255:
                                    client.seq -= 256

                            # Prepare the new packet. data_chunk can be empty, and in this case this packet only serves
                            # as an ACK for a received data, or it can piggyback on an ack if it has data
                            # (beautiful, isn't it?)
                            data_ack_packet = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / \
                                              RE(sid=pkt[RE].sid, flags="A", seq=client.seq, ack=client.ack) / \
                                              Raw(load=data_chunk)

                            # If we sen't data, we expect an ACK back, so we trigger the ARQ thread.
                            has_data = data_chunk != ""

                            # Send the data!
                            self.new_send(data_ack_packet, client=client, expect_ack=has_data)

                            return

            else:
                # Wake up the ARQ task and finish it - we got the response we expected. sort of.
                self.got_ack(client, pkt)
                self.general_error(protocol_errors.INITIALIZATION_DIDNT_FINISH, client, pkt, 1)

        # Handle FIN and FIN ACK packets that terminate a session.
        elif pkt[RE].flags == FLAG.FIN or pkt[RE].flags == (FLAG.FIN | FLAG.ACK):

            # If the session is initializing send error - we do not support FIN in session initialization.
            if client.socket_state == CLIENT_STATE.INITIATING_SESSION:
                # Session init is only relevant for syn and ack 0.
                if pkt[RE].seq == 0 and pkt[RE].ack == 0:
                    # Send an error
                    self.general_error(protocol_errors.INIT_DIDNT_FINISH_FIN_IS_ILLEGAL, client, pkt, 1)
                    return

            # Handle the FIN if the session is in an activated state.
            if client.socket_state == CLIENT_STATE.SESSION_ACTIVATED:

                # Verify that the seq/ack match what the client currently has.
                if pkt[RE].ack == client.seq and pkt[RE].seq == client.ack:
                    # If the other party requires an ACK, prepare to send it.
                    if pkt[RE].flags & FLAG.ACK != 0:
                        # TODO - should those lines be used?
                        # sid = client.sid_generated
                        # if sid == -1:
                        #    sid = client.sid_received
                        self.got_ack(client, pkt)
                        response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / RE(sid=pkt[RE].sid, flags="F",
                                                                                           seq=pkt[RE].ack,
                                                                                           ack=pkt[RE].seq)

                        client.socket_state = CLIENT_STATE.RECEIVED_FIN
                        self.new_send(response, client=client, expect_ack=False)
                    else:
                        # TODO: should have it?
                        # Wake up the ARQ task and finish it - we got the response we expected.
                        self.got_ack(client, pkt)

                    # Whether you ACK or not, start wrapping up the session.
                    client.finish_session()
                    return

            if client.socket_state == CLIENT_STATE.WAITING_FIN:
                if pkt[RE].ack == client.seq and pkt[RE].seq == client.ack:
                    # Wake up the ARQ task and finish it - we got the response we expected.
                    self.got_ack(client, pkt)
                    client.finish_session()
                    return

        # Handle packets with the error flag set. Make sure they have the correct
        # seq and ack.
        elif pkt[RE].flags & FLAG.ERR != 0:
            if pkt[RE].ack == client.seq and pkt[RE].seq == client.ack:

                # See if an error code or description was transmitted, and if so,
                # return it through the IPC.
                packet_error = None
                if len(pkt[Raw].load) >= 2:
                    err_code = struct.unpack("<H", pkt[Raw].load[:2])[0]
                    err_desc = pkt[Raw].load[2:]
                    packet_error = ErrorTuple(err_code, err_desc)

                # Finish the session
                client.finish_session(error=packet_error)

        # Handle any other combination of packets
        else:
            # If we FIN we don't want to start answering stuff. Also, make sure seq and
            # ack make sense, otherwise this is not a relevant packet.
            if client.socket_state != CLIENT_STATE.WAITING_FIN and pkt[RE].ack == client.seq and \
                            pkt[RE].seq == client.ack:
                self.general_error(protocol_errors.ILLEGAL_FLAG_COMBINATION, client, pkt, 1)
                return

    # This function can be called on multiple occasions - a wrong packet, session
    # terminated abruptly, or all sorts of stuff.
    # If a response is specified, the wrong packet is going to be answered with a
    # matching error.
    # If a client is specified, the client will start a process of closing a session.
    def general_error(self, err, client=None, pkt=None, respond=0):
        if respond and pkt:
            # Generate an error packet and send it. We do not expect ACK for an error packet obviously.
            err_response = YO(src=self.yo_addr, dst=pkt[YO].src, opcode="RE") / RE(sid=pkt[YO].sid,
                                                                                   flags="E") / Raw(
                load=struct.pack("<H", err.code) + err.description)
            self.new_send(err_response, client=client)
        # If a client is specified - close the client. We do not keep or recover
        # clients that has erred.
        if client:
            with self.client_list_lock:
                client.finish_session(error=err)


    def handle_arp_packet(self, pkt):
        """
        Handle an incoming ARP Packets.
        We handle both ARP requests aimed at us, and ARP Answers that are sent over the network.
        We use general answers to enrich our cache.
        :param pkt: pkt
        """
        # Check that the protocol type is 0x9999 - Hardcoded and made up number.
        if pkt[YOARP].ptype == 0x9999:
            # Check if the operation is a question
            if pkt[YOARP].op == 1:
                # Answer for ARPs that are directed for us
                # (if we already registered a YO address)
                if self.yo_addr:
                    if pkt[YOARP].pdst == self.yo_addr:
                        # NOTE: This is really weird - pkt.src. I'd expect pkt[Ether].src but it just wouldn't
                        # work. So this does.
                        # For an explanation of the next two lines please refer to the "register" function.
                        self.prints("Answering ARP from %s" % pkt[YOARP].psrc, 3)
                        arp_answer = Ether(src=self.src_mac, dst=pkt.src) / YOARP(psrc=self.yo_addr, pdst=pkt[YOARP].psrc,
                                                                             op=2, hwsrc=self.src_mac,
                                                                             hwdst=pkt[YOARP].hwsrc)
                        # sendp(arp_answer)
                        self.L2socket.send(arp_answer)


            # Passive cache ARPs
            # This is bad on purpose so that attacks can get interesting (Even though ARP attacks are
            # not a part of Gvahim curriculum, so don't exploit this!).
            # Unless we already have something cached (which should be 120 seconds), we simply check if
            # op is 2 (answer) and can inject pretty much whatever we want. This is a serious implementation bug.
            # What if we inject 00:00:00:00:00:00 or ff:ff:ff:ff:ff:ff? What if we hijack our own IP?
            # That's where things can get messy.

            if pkt[YOARP].op == 2:
                # Check against scapy's internal yoarp_cache.
                mac = conf.netcache.yoarp_cache.get(pkt[YOARP].psrc)
                if mac is None:
                    conf.netcache.yoarp_cache[pkt[YOARP].psrc] = pkt[YOARP].hwsrc

    def register(self, yoip):
        """
        This function attempts to acquire a lock on a YO address and "register" it on the network.
        What this really means, is that we try to see if anyone has our YO address already registered.
        If not, we treat this address as our own and advertise ourselves as the owners of this address.
        We will also start answering ARP queries that our MAC is associated with this YO address.
        If the address is already registered to someone else, we quietly go back to our cave and cry.
        :param yoip: A.B address to try to register
        """
        self.prints( "Trying to acquire YO Address %s" % yoip, 4)

        # This part is a little hacky and important to understand. Scapy, and the
        # computer for that matter, do not know which interface is associated with our YO address.
        # Since we want to be able to send packets anywhere on the network, we need to find the
        # interface that will allow us to do so (and it's MAC address, for ARP packets). Usually,
        # it's eth0, but not necessarily. Hence, we acquire the correct interface by assuming that
        # 0.0.0.0 is an IPv4 address that will always have the interface set up correctly. If you'd
        # like to see what I'm talking about, use scapy's conf.route.route and see the routing table.
        # So, TLDR - We ge the correct MAC address.

        # Ask who-has our YO address
        pkt = Ether(src=self.src_mac, dst=ETHER_BROADCAST) / YOARP(op="who-has", hwsrc=self.src_mac, psrc="0.0", pdst=yoip)

        res = srp1(pkt,
                   iface=self.iface,
                   timeout=0.2,
                   verbose=0,
                   retry=1,
                   nofilter=1)

        if res is not None:
            # if (self._convert_yoip_to_num(res[YOARP].psrc) == yoip):
            self.prints( "Error! YO Address %s is present on network, acquisition failed!" % yoip, 4)
            return False

        # If no one answered the ARP question we can assume no one has our YO address!
        self.yo_addr = yoip
        register_yoip(yoip)



        # Announce in broadcast, I'm the king of this castle!
        arp_notification = Ether(src=self.src_mac, dst="ff:ff:ff:ff:ff:ff") / YOARP(psrc=self.yo_addr, op=2, hwsrc=self.src_mac)

        # sendp(arp_notification, verbose=0)
        self.L2socket.send(arp_notification)

        self.prints( "Successfully acquired address %s and broadcast it to network!" % yoip, 4)
        return True
