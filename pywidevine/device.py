import base64

from Crypto.PublicKey import RSA

from google.protobuf.message import DecodeError

from pywidevine.license_protocol_pb2 import ClientIdentification, DrmCertificate, FileHashes, SignedDrmCertificate

from pywidevine.utils import BinaryReader

class DeviceTypes:
    CHROME = 1
    ANDROID = 2


class Device:
    def __init__(
        self,
        type_,
        security_level,
        flags,
        private_key,
        client_id,
    ):
        """
        This is the device key data that is needed for the CDM (Content Decryption Module).

        Parameters:
            type_: Device Type
            security_level: Security level from 1 (the highest ranking) to 3 (the lowest ranking)
            flags: Extra flags
            private_key: Device Private Key
            client_id: Device Client Identification Blob
        """
        # *_,*__ is to ignore unwanted args, like signature and version from the struct

        if not client_id:
            raise ValueError("Client ID is required, the WVD does not contain one or is malformed.")
        if not private_key:
            raise ValueError("Private Key is required, the WVD does not contain one or is malformed.")

        self.type = type_
        self.security_level = security_level
        self.flags = flags or {}
        self.private_key = RSA.importKey(private_key)
        self.client_id = ClientIdentification()
        try:
            self.client_id.ParseFromString(client_id)
            if self.client_id.SerializeToString() != client_id:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError("Failed to parse client_id as a ClientIdentification, {0}".format(e))

        self.vmp = FileHashes()
        if self.client_id.vmp_data:
            try:
                self.vmp.ParseFromString(self.client_id.vmp_data)
                if self.vmp.SerializeToString() != self.client_id.vmp_data:
                    raise DecodeError("partial parse")
            except DecodeError as e:
                raise DecodeError("Failed to parse Client ID's VMP data as a FileHashes, {0}".format(e))

        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        try:
            signed_drm_certificate.ParseFromString(self.client_id.token)
            if signed_drm_certificate.SerializeToString() != self.client_id.token:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError("Failed to parse the Signed DRM Certificate of the Client ID, {0}".format(e))

        try:
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            if drm_certificate.SerializeToString() != signed_drm_certificate.drm_certificate:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError("Failed to parse the DRM Certificate of the Client ID, {0}".format(e))

        self.system_id = drm_certificate.system_id

    def __repr__(self):
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join(["{0}={1}".format(k, repr(v)) for k, v in self.__dict__.items()])
        )

    @classmethod
    def loads(cls, data):
        reader = BinaryReader(data, little_endian=False)
        signature = reader.read_bytes(3)
        version = reader.read_int(1)
        type = reader.read_int(1)
        security_level = reader.read_int(1)
        flags = reader.read_int(1)
        private_key_len = reader.read_int(2)
        private_key = reader.read_bytes(private_key_len)
        client_id_len = reader.read_int(2)
        client_id = reader.read_bytes(client_id_len)

        if reader.has_data():
            vmp_len = reader.read_int(2)
            vmp = reader.read_bytes(vmp_len)
        else:
            vmp_len = 0
            vmp = b''

        flags = {}
        return cls(type, security_level, flags, private_key, client_id)

    @classmethod
    def load(cls, path):
        with open(path, mode="rb") as f:
            return cls.loads(f.read())


__all__ = ("Device", "DeviceTypes")
