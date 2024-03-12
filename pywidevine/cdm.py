
import base64
import binascii
import random
import sys
import time
from uuid import UUID

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import CMAC, HMAC, SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_PSS as pss
from Crypto.Util import Padding
from google.protobuf.message import DecodeError

from pywidevine.device import Device, DeviceTypes
from pywidevine.exceptions import (InvalidContext, InvalidInitData, InvalidLicenseMessage, InvalidLicenseType,
                                   InvalidSession, NoKeysLoaded, SignatureMismatch, TooManySessions)
from pywidevine.key import Key
from pywidevine.license_protocol_pb2 import (ClientIdentification, DrmCertificate, EncryptedClientIdentification,
                                             License, LicenseRequest, LicenseType, SignedDrmCertificate,
                                             SignedMessage)
from pywidevine.pssh import PSSH
from pywidevine.session import Session

from pywidevine.utils import to_bytes


class Cdm:
    uuid = UUID(bytes=b"\xed\xef\x8b\xa9\x79\xd6\x4a\xce\xa3\xc8\x27\xdc\xd5\x1d\x21\xed")
    urn = "urn:uuid:{0}"
    key_format = urn.format(uuid)
    service_certificate_challenge = b"\x08\x04"
    common_privacy_cert = (
        # Used by Google's production license server (license.google.com)
        # Not publicly accessible directly, but a lot of services have their own gateways to it
        "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEE"
        "Qa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3r"
        "M3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ"
        "7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmlu"
        "ZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/C"
        "CpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2"
        "/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeF"
        "Hd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98"
        "X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ=")
    staging_privacy_cert = (
        # Used by Google's staging license server (staging.google.com)
        # This can be publicly accessed without authentication using https://cwip-shaka-proxy.appspot.com/no_auth
        "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8"
        "MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+"
        "FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fz"
        "PvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUu"
        "Y29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19"
        "ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv"
        "1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocL"
        "sjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6W"
        "nCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU")
    root_signed_cert = SignedDrmCertificate()
    root_signed_cert.ParseFromString(base64.b64decode(
        "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZy"
        "f7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfM"
        "qIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx"
        "+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg1"
        "7B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSC"
        "UNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0a"
        "y5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZV"
        "dA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2F"
        "RXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7"
        "evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
    ))
    root_cert = DrmCertificate()
    root_cert.ParseFromString(root_signed_cert.drm_certificate)

    MAX_NUM_OF_SESSIONS = 16

    def __init__(
        self,
        device_type,
        system_id,
        security_level,
        client_id,
        rsa_key
    ):
        """Initialize a Widevine Content Decryption Module (CDM)."""
        if not device_type:
            raise ValueError("Device Type must be provided")

        if not system_id:
            raise ValueError("System ID must be provided")
        if not isinstance(system_id, int):
            raise TypeError("Expected system_id to be a {0} not {1}".format(int, system_id))

        if not security_level:
            raise ValueError("Security Level must be provided")
        if not isinstance(security_level, int):
            raise TypeError("Expected security_level to be a {0} not {1}".format(int, security_level))

        if not client_id:
            raise ValueError("Client ID must be provided")
        if not isinstance(client_id, ClientIdentification):
            raise TypeError("Expected client_id to be a {0} not {1}".format(ClientIdentification, client_id))

        if not rsa_key:
            raise ValueError("RSA Key must be provided")

        self.device_type = device_type
        self.system_id = system_id
        self.security_level = security_level
        self.__client_id = client_id

        self.__signer = pss.new(rsa_key)
        self.__decrypter = PKCS1_OAEP.new(rsa_key)

        self.__sessions = {}

    @classmethod
    def from_device(cls, device):
        """Initialize a Widevine CDM from a Widevine Device (.wvd) file."""
        return cls(
            device_type=device.type,
            system_id=device.system_id,
            security_level=device.security_level,
            client_id=device.client_id,
            rsa_key=device.private_key
        )

    def open(self):
        """
        Open a Widevine Content Decryption Module (CDM) session.

        Raises:
            TooManySessions: If the session cannot be opened as limit has been reached.
        """
        if len(self.__sessions):
            raise TooManySessions("Too many Sessions open ({0}).".format(self.MAX_NUM_OF_SESSIONS))

        session = Session(len(self.__sessions) + 1)
        self.__sessions[session.id] = session

        return session.id

    def close(self, session_id):
        """
        Close a Widevine Content Decryption Module (CDM) session.

        Parameters:
            session_id: Session identifier.

        Raises:
            InvalidSession: If the Session identifier is invalid.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0} is invalid.".format(session_id))
        del self.__sessions[session_id]

    def set_service_certificate(self, session_id, certificate):
        """
        Set a Service Privacy Certificate for Privacy Mode. (optional but recommended)

        The Service Certificate is used to encrypt Client IDs in Licenses. This is also
        known as Privacy Mode and may be required for some services or for some devices.
        Chrome CDM requires it as of the enforcement of VMP (Verified Media Path).

        We reject direct DrmCertificates as they do not have signature verification and
        cannot be verified. You must provide a SignedDrmCertificate or a SignedMessage
        containing a SignedDrmCertificate.

        Parameters:
            session_id: Session identifier.
            certificate: SignedDrmCertificate (or SignedMessage containing one) in Base64
                or Bytes form obtained from the Service. Some services have their own,
                but most use the common privacy cert, (common_privacy_cert). If None, it
                will remove the current certificate.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            DecodeError: If the certificate could not be parsed as a SignedDrmCertificate
                nor a SignedMessage containing a SignedDrmCertificate.
            SignatureMismatch: If the Signature of the SignedDrmCertificate does not
                match the underlying DrmCertificate.

        Returns the Service Provider ID of the verified DrmCertificate if successful.
        If certificate is None, it will return the now-unset certificate's Provider ID,
        or None if no certificate was set yet.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0} is invalid.".format(session_id))

        if certificate is None:
            if session.service_certificate:
                drm_certificate = DrmCertificate()
                drm_certificate.ParseFromString(session.service_certificate.drm_certificate)
                provider_id = drm_certificate.provider_id
            else:
                provider_id = None
            session.service_certificate = None
            return provider_id

        if isinstance(certificate, str):
            try:
                certificate = base64.b64decode(certificate)  # assuming base64
            except binascii.Error:
                raise DecodeError("Could not decode certificate string as Base64, expected bytes.")
        elif not isinstance(certificate, bytes):
            raise DecodeError("Expecting Certificate to be bytes, not {0}".format(certificate))

        signed_message = SignedMessage()
        signed_drm_certificate = SignedDrmCertificate()
        drm_certificate = DrmCertificate()

        try:
            signed_message.ParseFromString(certificate)
            if all(
                # See https://github.com/devine-dl/pywidevine/issues/41
                bytes(chunk) == signed_message.SerializeToString()
                for chunk in zip(*[iter(certificate)] * len(signed_message.SerializeToString()))
            ):
                signed_drm_certificate.ParseFromString(signed_message.msg)
            else:
                signed_drm_certificate.ParseFromString(certificate)
                if signed_drm_certificate.SerializeToString() != certificate:
                    raise DecodeError("partial parse")
        except DecodeError as e:
            # could be a direct unsigned DrmCertificate, but reject those anyway
            raise DecodeError("Could not parse certificate as a SignedDrmCertificate, {0}".format(e))

        try:
            pss. \
                new(RSA.import_key(self.root_cert.public_key)). \
                verify(
                    msg_hash=SHA1.new(signed_drm_certificate.drm_certificate),
                    signature=signed_drm_certificate.signature
                )
        except (ValueError, TypeError):
            raise SignatureMismatch("Signature Mismatch on SignedDrmCertificate, rejecting certificate")

        try:
            drm_certificate.ParseFromString(signed_drm_certificate.drm_certificate)
            if drm_certificate.SerializeToString() != signed_drm_certificate.drm_certificate:
                raise DecodeError("partial parse")
        except DecodeError as e:
            raise DecodeError("Could not parse signed certificate's message as a DrmCertificate, {0}".format(e))

        # must be stored as a SignedDrmCertificate as the signature needs to be kept for RemoteCdm
        # if we store as DrmCertificate (no signature) then RemoteCdm cannot verify the Certificate
        session.service_certificate = signed_drm_certificate
        return drm_certificate.provider_id

    def get_service_certificate(self, session_id):
        """
        Get the currently set Service Privacy Certificate of the Session.

        Parameters:
            session_id: Session identifier.

        Raises:
            InvalidSession: If the Session identifier is invalid.

        Returns the Service Certificate if one is set, otherwise None.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0} is invalid.".format(session_id))

        return session.service_certificate

    def get_license_challenge(
        self,
        session_id,
        pssh,
        license_type = "STREAMING",
        privacy_mode = True
    ):
        """
        Get a License Request (Challenge) to send to a License Server.

        Parameters:
            session_id: Session identifier.
            pssh: PSSH Object to get the init data from.
            license_type: Type of License you wish to exchange, often `STREAMING`.
                - "STREAMING": Normal one-time-use license.
                - "OFFLINE": Offline-use licence, usually for Downloaded content.
                - "AUTOMATIC": License type decision is left to provider.
            privacy_mode: Encrypt the Client ID using the Privacy Certificate. If the
                privacy certificate is not set yet, this does nothing.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidInitData: If the Init Data (or PSSH box) provided is invalid.
            InvalidLicenseType: If the type_ parameter value is not a License Type. It
                must be a LicenseType enum, or a string/int representing the enum's keys
                or values.

        Returns a SignedMessage containing a LicenseRequest message. It's signed with
        the Private Key of the device provision.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0} is invalid.".format(session_id))

        if not pssh:
            raise InvalidInitData("A pssh must be provided.")
        if not isinstance(pssh, PSSH):
            raise InvalidInitData("Expected pssh to be a {0}, not {1}".format(PSSH, pssh))

        if not isinstance(license_type, str):
            raise InvalidLicenseType("Expected license_type to be a {0}, not {1}".format(str, license_type))
        if license_type not in LicenseType.keys():
            raise InvalidLicenseType(
                "Invalid license_type value of '{0}'. Available values: {1}".format(license_type, LicenseType.keys())
            )

        if self.device_type == DeviceTypes.ANDROID:
            # OEMCrypto's request_id seems to be in AES CTR Counter block form with no suffix
            # Bytes 5-8 does not seem random, in real tests they have been consecutive \x00 or \xFF
            # Real example: A0DCE548000000000500000000000000
            request_id = (get_random_bytes(4) + (b"\x00" * 4))  # (?)
            request_id += to_bytes(session.number, 8, 'little') # counter
            # as you can see in the real example, it is stored as uppercase hex and re-encoded
            # it's really 16 bytes of data, but it's stored as a 32-char HEX string (32 bytes)
            request_id = binascii.hexlify(request_id).upper()
            #print('request_id=%r' % request_id)
        else:
            request_id = get_random_bytes(16)

        license_request = LicenseRequest(
            client_id=(
                self.__client_id
            ) if not (session.service_certificate and privacy_mode) else None,
            encrypted_client_id=self.encrypt_client_id(
                client_id=self.__client_id,
                service_certificate=session.service_certificate
            ) if session.service_certificate and privacy_mode else None,
            content_id=LicenseRequest.ContentIdentification(
                widevine_pssh_data=LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data=[pssh.init_data],  # either a WidevineCencHeader or custom data
                    license_type=license_type,
                    request_id=request_id
                )
            ),
            type="NEW",
            request_time=int(time.time()),
            protocol_version="VERSION_2_1",
            key_control_nonce=random.randrange(1, 2 ** 31),
        ).SerializeToString()

        signed_license_request = SignedMessage(
            type="LICENSE_REQUEST",
            msg=license_request,
            signature=self.__signer.sign(SHA1.new(license_request))
        ).SerializeToString()

        session.context[request_id] = self.derive_context(license_request)

        return signed_license_request

    def parse_license(self, session_id, license_message):
        """
        Load Keys from a License Message from a License Server Response.

        License Messages can only be loaded a single time. An InvalidContext error will
        be raised if you attempt to parse a License Message more than once.

        Parameters:
            session_id: Session identifier.
            license_message: A SignedMessage containing a License message.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            InvalidLicenseMessage: The License message could not be decoded as a Signed
                Message or License message.
            InvalidContext: If the Session has no Context Data. This is likely to happen
                if the License Challenge was not made by this CDM instance, or was not
                by this CDM at all. It could also happen if the Session is closed after
                calling parse_license but not before it got the context data.
            SignatureMismatch: If the Signature of the License SignedMessage does not
                match the underlying License.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0} is invalid.".format(session_id))

        if not license_message:
            raise InvalidLicenseMessage("Cannot parse an empty license_message")

        if isinstance(license_message, bytes):
            signed_message = SignedMessage()
            try:
                signed_message.ParseFromString(license_message)
                if signed_message.SerializeToString() != license_message:
                    raise DecodeError(license_message)
            except DecodeError as e:
                raise InvalidLicenseMessage("Could not parse license_message as a SignedMessage, {0}".format(e))
            license_message = signed_message

        if not isinstance(license_message, SignedMessage):
            raise InvalidLicenseMessage("Expecting license_response to be a SignedMessage, got {0}".format(license_message))

        if license_message.type != SignedMessage.MessageType.Value("LICENSE"):
            raise InvalidLicenseMessage(
                "Expecting a LICENSE message, not a '{0}' message.".format(SignedMessage.MessageType.Name(license_message.type))
            )

        licence = License()
        licence.ParseFromString(license_message.msg)

        context = session.context.get(licence.id.request_id)
        if not context:
            raise InvalidContext("Cannot parse a license message without first making a license request")

        enc_key, mac_key_server, _ = self.derive_keys(
            *context,
            key=self.__decrypter.decrypt(license_message.session_key)
        )

        # 1. Explicitly use the original `license_message.msg` instead of a re-serializing from `licence`
        #    as some differences may end up in the output due to differences in the proto schema
        # 2. The oemcrypto_core_message (unknown purpose) is part of the signature algorithm starting with
        #    OEM Crypto API v16 and if available, must be prefixed when HMAC'ing a signature.

        mac = HMAC.new(mac_key_server, digestmod=SHA256)
        mac.update(license_message.oemcrypto_core_message or b"")
        mac.update(license_message.msg)
        computed_signature = mac.digest()
        del mac

        if license_message.signature != computed_signature:
            raise SignatureMismatch("Signature Mismatch on License Message, rejecting license")

        session.keys = [
            Key.from_key_container(key, enc_key)
            for key in licence.key
        ]

        del session.context[licence.id.request_id]

    def get_keys(self, session_id, type_ = None):
        """
        Get Keys from the loaded License message.

        Parameters:
            session_id: Session identifier.
            type_: (optional) Key Type to filter by and return.

        Raises:
            InvalidSession: If the Session identifier is invalid.
            TypeError: If the provided type_ is an unexpected value type.
            ValueError: If the provided type_ is not a valid Key Type.
        """
        session = self.__sessions.get(session_id)
        if not session:
            raise InvalidSession("Session identifier {0 is invalid.".format(session_id))

        try:
            if isinstance(type_, str):
                type_ = License.KeyContainer.KeyType.Value(type_)
            elif isinstance(type_, int):
                License.KeyContainer.KeyType.Name(type_)  # only test
            elif type_ is not None:
                raise TypeError("Expected type_ to be a {0} or int, not {1}".format(License.KeyContainer.KeyType, type_))
        except ValueError as e:
            raise ValueError("Could not parse type_ as a {0}, {1}".format(License.KeyContainer.KeyType, e))

        return [
            key
            for key in session.keys
            if not type_ or key.type == License.KeyContainer.KeyType.Name(type_)
        ]


    @staticmethod
    def encrypt_client_id(
        client_id,
        service_certificate,
        key = None,
        iv = None
    ):
        """Encrypt the Client ID with the Service's Privacy Certificate."""
        privacy_key = key or get_random_bytes(16)
        privacy_iv = iv or get_random_bytes(16)

        if isinstance(service_certificate, SignedDrmCertificate):
            drm_certificate = DrmCertificate()
            drm_certificate.ParseFromString(service_certificate.drm_certificate)
            service_certificate = drm_certificate
        if not isinstance(service_certificate, DrmCertificate):
            raise ValueError("Expecting Service Certificate to be a DrmCertificate, not {0}".format(service_certificate))

        encrypted_client_id = EncryptedClientIdentification(
            provider_id=service_certificate.provider_id,
            service_certificate_serial_number=service_certificate.serial_number,
            encrypted_client_id=AES.
            new(privacy_key, AES.MODE_CBC, privacy_iv).
            encrypt(Padding.pad(client_id.SerializeToString(), 16)),
            encrypted_client_id_iv=privacy_iv,
            encrypted_privacy_key=PKCS1_OAEP.
            new(RSA.importKey(service_certificate.public_key)).
            encrypt(privacy_key)
        )

        return encrypted_client_id

    @staticmethod
    def derive_context(message):
        """Returns 2 Context Data used for computing the AES Encryption and HMAC Keys."""

        def _get_enc_context(msg):
            label = b"ENCRYPTION"
            key_size = 16 * 8  # 128-bit
            return label + b"\x00" + msg + to_bytes(key_size, 4, "big")

        def _get_mac_context(msg):
            label = b"AUTHENTICATION"
            key_size = 32 * 8 * 2  # 512-bit
            return label + b"\x00" + msg + to_bytes(key_size, 4, "big")

        return _get_enc_context(message), _get_mac_context(message)

    @staticmethod
    def derive_keys(enc_context, mac_context, key):
        """
        Returns 3 keys derived from the input message.
        Key can either be a pre-provision device aes key, provision key, or a session key.

        For provisioning:
        - enc: aes key used for unwrapping RSA key out of response
        - mac_key_server: hmac-sha256 key used for verifying provisioning response
        - mac_key_client: hmac-sha256 key used for signing provisioning request

        When used with a session key:
        - enc: decrypting content and other keys
        - mac_key_server: verifying response
        - mac_key_client: renewals

        With key as pre-provision device key, it can be used to provision and get an
        RSA device key and token/cert with key as session key (OAEP wrapped with the
        post-provision RSA device key), it can be used to decrypt content and signing
        keys and verify licenses.
        """

        def _derive(session_key, context, counter):
            mac = CMAC.new(session_key, ciphermod=AES)
            mac.update(to_bytes(counter, 1, "big") + context)
            return mac.digest()

        enc_key = _derive(key, enc_context, 1)
        mac_key_server = _derive(key, mac_context, 1)
        mac_key_server += _derive(key, mac_context, 2)
        mac_key_client = _derive(key, mac_context, 3)
        mac_key_client += _derive(key, mac_context, 4)

        return enc_key, mac_key_server, mac_key_client


__all__ = ("Cdm",)
