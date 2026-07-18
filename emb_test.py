import base64
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Same temporary test key used on the ESP32
AES_KEY = bytes([
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
])

encrypted_payload = """
{"schema_version":1,"payload_type":"encrypted_telemetry","algorithm":"AES-128-GCM","node_id":"anoushka-node","nonce":"vj5it9nRTC6V8uZb","ciphertext":"S1PxSpCiCfGdklqzVB+OOkm/R+Jvt9Kj3czkdEFSEtzhn5C+7LWQWR58zzp48PGu1OZyECdmObxDVfeSzkJ3fzoPhNRIoL7Xf2Rz2S8Wizr9cp6Djs+NI+g0z7sQlziL4P7DSOVMPg4Ih02WTOeuChECvguXjQMoceC9QxGabuGfz0NUmdKZNbhN8C6RIr2RnIe4TDCxJnYr45VFIKL8FuDxoWe5LSKTtmKLvbfAkjPrmXfQgnz3a7v+6SUyS2qdpZSRQ+K0kX7XvRoRFBwvqcpJ1eu+XA3discOZyrM0zUgjdM9n3ZirUd3/XDMc9msXlLn3qGiPdka+v6Qe+//E376xhe+4bm+/QyFROUEWXLrzITAtSZE4oOnsU64zgIwHvNvYEzIypYTvH5L+93mfqHeBIHEzeQu1CPRBxnrDviwPq4KSNLeNGxg+Q7MaBKklUmvbuQBmy34pVx+rdBoEvChMSwI6uHh9y/1/I2QSLcW5yR7gacU2w36YoWVzZs2+HlRbZB2j4IhPRmxcb0xcULKBlt6Z7/C","tag":"97Ful8YAinlgt7dPxUIFBg=="}
""".strip()


payload = json.loads(encrypted_payload)

nonce = base64.b64decode(payload["nonce"])
ciphertext = base64.b64decode(payload["ciphertext"])
tag = base64.b64decode(payload["tag"])

aesgcm = AESGCM(AES_KEY)

# Python expects the authentication tag appended to the ciphertext
plaintext = aesgcm.decrypt(
    nonce,
    ciphertext + tag,
    None
)

print("Decryption successful!")
print(plaintext.decode("utf-8"))