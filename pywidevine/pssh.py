import base64
import binascii
import string
from uuid import UUID

from google.protobuf.message import DecodeError
from pywidevine.license_protocol_pb2 import WidevinePsshData

from pywidevine.utils import Pssh, parse_boxes, BinaryReader
import re

class PSSH:
    """
    MP4 PSSH Box-related utilities.
    Allows you to load, create, and modify various kinds of DRM system headers.
    """

    class SystemId:
        Widevine = UUID(hex="edef8ba979d64acea3c827dcd51d21ed")
        PlayReady = UUID(hex="9a04f07998404286ab92e65be0885f95")

    def __init__(self, data, type='mp4box', strict = False):
        if not data:
            raise ValueError("Data must not be empty.")
        
        if type == None:
            type = 'playready' if "</WRMHEADER>".encode("utf-16-le") in data else 'widevine'

        if type == 'mp4box':
            pssh = parse_boxes(data)[0]
        elif type == 'widevine':
            widevine_pssh_data = WidevinePsshData()
            widevine_pssh_data.ParseFromString(data)
            data_serialized = widevine_pssh_data.SerializeToString()
            if data_serialized != data:  # not actually a WidevinePsshData
                raise DecodeError()
            pssh = Pssh(0,  PSSH.SystemId.Widevine, None, data)
        elif type == 'playready':
            pssh = Pssh(0,  PSSH.SystemId.PlayReady, None, data)
        else:
            pssh = Pssh(0,  PSSH.SystemId.Widevine, None, data)

        self.version = pssh.version
        self.flags = 0
        self.system_id = pssh.system_id
        self.__key_ids = pssh.key_ids
        self.init_data = pssh.pssh_data

        #print("PSSH<%r>(v%r; %r, %r, %r)" % (self.system_id, self.version, self.flags, self.__key_ids, self.init_data))

    def to_widevine(self):
        if self.system_id == PSSH.SystemId.Widevine:
            raise ValueError("This is already a Widevine PSSH")

        widevine_pssh_data = WidevinePsshData(
            key_ids=[x.bytes for x in self.key_ids()],
            algorithm="AESCTR"
        )

        if self.version == 1:
            # ensure both cenc header and box has same Key IDs
            # v1 uses both this and within init data for basically no reason
            self.__key_ids = self.key_ids()

        self.init_data = widevine_pssh_data.SerializeToString()
        self.system_id = PSSH.SystemId.Widevine

    def key_ids(self):
        if self.version == 1 and self.__key_ids:
            return self.__key_ids

        if self.system_id == PSSH.SystemId.Widevine:
            # TODO: What if its not a Widevine Cenc Header but the System ID is set as Widevine?
            cenc_header = WidevinePsshData()
            cenc_header.ParseFromString(self.init_data)
            keysList = []
            for key_id in cenc_header.key_ids:
                key = ( UUID(bytes=key_id) if len(key_id) == 16 else  # normal
                        UUID(hex=key_id.decode()) if len(key_id) == 32 else  # stored as hex
                        UUID(int=int.from_bytes(key_id, "big"))  # assuming as number
                       )
                keysList.append(key)
            return keysList


        if self.system_id == PSSH.SystemId.PlayReady:
            # Assuming init data is a PRO (PlayReadyObject)
            # https://learn.microsoft.com/en-us/playready/specifications/playready-header-specification
            reader = BinaryReader(self.init_data, little_endian=True)

            pro_length = reader.read_int(4)
            if pro_length != len(self.init_data):
                raise ValueError("The PlayReadyObject seems to be corrupt (too big or small, or missing data).")
            pro_record_count = reader.read_int(2)

            for _ in range(pro_record_count):
                prr_type = reader.read_int(2)
                prr_length = reader.read_int(2)
                prr_value = reader.read_bytes(prr_length)
                if prr_type != 0x01:
                    # No PlayReady Header, skip and hope for something else
                    # TODO: Add support for Embedded License Stores (0x03)
                    continue

                xml = prr_value.decode("utf-16-le")
                key_ids = re.compile('<KID>([A-Za-z0-9_+/=]+)</KID>').findall(xml)
                return [
                    UUID(bytes=base64.b64decode(key_id))
                    for key_id in key_ids
                ]

__all__ = ("PSSH",)
