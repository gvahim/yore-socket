"""
Author: YochaiE
Date: 09.02.2016

Description:
A helper library. Contains the IPC serialization methods that are used both by the
resocket and the resocket_daemon.
We assume in a lot of places that the data is in the correct format. Additional hardening might be
a good idea, even though no one is supposed to hack this layer :).
"""

import struct
from YOREException import YOREException


class Serializer(object):
    """
    The IPC serialization helper class.
    """

    # A list of results returned by the ProtocolDaemon.
    RESULT_SUCCESS = 0
    RESULT_ERROR = 0xFFFFFFFF

    # An IPC header size is always 8 bytes long - 4 Type and 4 Length.
    TLV_HEADER_SIZE = 8

    # We support 2 types of objects to serialize - int and string (how convenient)
    TYPE_INT = 0
    TYPE_STRING = 1

    # These are not the droid's you're looking for. Move along!
    def __init__(self):
        pass

    def serialize(self, cmd, args):
        """
        Serialize IPC data. Requires a cmd (hopefully one from the list), and
        a list of argument to serialize. The arguments must be of type int, long or string.
        :param cmd:  enum
        :param args: [args]
        :return: [data]
        """
        # Cmd must be a number.
        if (not isinstance(cmd, int)) and (not isinstance(cmd, long)):
            raise YOREException("Error! cmd must be a number!")

        data = struct.pack("<I", cmd)
        tmp_data = ""

        for arg in args:
            if isinstance(arg, int) or isinstance(arg, long):
                arg_data = struct.pack("<III", self.TYPE_INT, 4, arg)
            elif isinstance(arg, str):
                arg_data = struct.pack("<II", self.TYPE_STRING, len(arg)) + arg
            else:
                raise YOREException("Error identifying type and serializing")

            tmp_data += arg_data

        data += struct.pack("<I", len(tmp_data)) + tmp_data

        return data

    def deserialize(self, data):
        """
        deserialize received data into a CMD/RESULT format and a list of args.
        :param data: array
        :return: (cmd, args)
        """
        # Assume two DWORD(s) at first - cmd/result and data length.
        cmd = struct.unpack("<I", data[0:4])[0]
        data_length = struct.unpack("<I", data[4:8])[0]

        # Start parsing through the data. Assume we got enough data.
        # Once a TLV processing has been finished, append the arg to a list of args.
        i = 0
        args = []
        while i < data_length:
            arg_type = struct.unpack("<I", data[i + 8:i + 12])[0]
            arg_length = struct.unpack("<I", data[i + 12:i + 16])[0]
            if arg_type == self.TYPE_INT:
                arg_data = struct.unpack("<I", data[i + 16:i + 16 + arg_length])[0]
            elif arg_type == self.TYPE_STRING:
                arg_data = data[i + 16:i + 16 + arg_length]
            else:
                raise YOREException("Error deserialize data")

            i += arg_length + 8
            args.append(arg_data)

        return cmd, args
