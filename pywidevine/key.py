import base64
from uuid import UUID

from Crypto.Cipher import AES
from Crypto.Util import Padding

from pywidevine.license_protocol_pb2 import License


class Key:
    def __init__(self, type_, kid, key, permissions = None):
        self.type = type_
        self.kid = kid
        self.key = key
        self.permissions = permissions or []

    def __repr__(self):
        return "{name}({items})".format(
            name=self.__class__.__name__,
            items=", ".join(["{0}={1}".format(k, repr(v)) for k, v in self.__dict__.items()])
        )

    @classmethod
    def from_key_container(cls, key, enc_key):
        """Load Key from a KeyContainer object."""
        permissions = []
        if key.type == License.KeyContainer.KeyType.Value("OPERATOR_SESSION"):
            for descriptor, value in key.operator_session_key_permissions.ListFields():
                if value == 1:
                    permissions.append(descriptor.name)

        return Key(
            type_=License.KeyContainer.KeyType.Name(key.type),
            kid=cls.kid_to_uuid(key.id),
            key=Padding.unpad(
                AES.new(enc_key, AES.MODE_CBC, key.iv).decrypt(key.key),
                16
            ),
            permissions=permissions
        )

    @staticmethod
    def kid_to_uuid(kid):
        """
        Convert a Key ID from a string or bytes to a UUID object.
        At first this may seem very simple but some types of Key IDs
        may not be 16 bytes and some may be decimal vs. hex.
        """

        if not kid:
            kid = b"\x00" * 16

        if kid.decode(errors="replace").isdigit():
            return UUID(int=int(kid.decode()))

        if len(kid) < 16:
            kid += b"\x00" * (16 - len(kid))

        return UUID(bytes=kid)


__all__ = ("Key",)
