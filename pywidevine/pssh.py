import base64
import binascii
import string
from uuid import UUID

from google.protobuf.message import DecodeError
from pywidevine.license_protocol_pb2 import WidevinePsshData

from pywidevine.utils import Pssh, parse_boxes


class PSSH:
    """
    MP4 PSSH Box-related utilities.
    Allows you to load, create, and modify various kinds of DRM system headers.
    """

    class SystemId:
        Widevine = UUID(hex="edef8ba979d64acea3c827dcd51d21ed")
        PlayReady = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(self, data, strict = False):
        if not data:
            raise ValueError("Data must not be empty.")

        pssh = None
        try:
            pssh = parse_boxes(data)[0]
        except Exception as e:
            #print(e)
            try:
                widevine_pssh_data = WidevinePsshData()
                widevine_pssh_data.ParseFromString(data)
                data_serialized = widevine_pssh_data.SerializeToString()
                if data_serialized != data:  # not actually a WidevinePsshData
                    raise DecodeError()
                pssh = Pssh(0,  PSSH.SystemId.Widevine, None, data)
            except DecodeError:  # not a widevine cenc header
                if "</WRMHEADER>".encode("utf-16-le") in data:
                    # TODO: Actually parse `data` as a PlayReadyHeader object and store that instead
                    box = Box.parse(Box.build(dict(
                        type=b"pssh",
                        version=0,
                        flags=0,
                        system_ID=PSSH.SystemId.PlayReady,
                        init_data=data
                    )))
                elif strict:
                    raise DecodeError("Could not parse data as a {0}.".format(WidevinePsshData))
                else:
                    # Data is not a WidevineCencHeader nor a PlayReadyHeader.
                    # The license server likely has something custom to parse it.
                    # See doc-string about Lenient mode for more information.
                    box = Box.parse(Box.build(dict(
                        type=b"pssh",
                        version=0,
                        flags=0,
                        system_ID=PSSH.SystemId.Widevine,
                        init_data=data
                    )))

        self.version = pssh.version
        self.flags = 0
        self.system_id = pssh.system_id
        self.__key_ids = pssh.key_ids
        self.init_data = pssh.pssh_data

        #print("PSSH<%r>(v%r; %r, %r, %r)" % (self.system_id, self.version, self.flags, self.__key_ids, self.init_data))




__all__ = ("PSSH",)
