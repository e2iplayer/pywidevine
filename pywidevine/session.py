from Crypto.Random import get_random_bytes

class Session:
    def __init__(self, number):
        self.number = number
        self.id = get_random_bytes(16)
        self.service_certificate = None
        self.context = {}
        self.keys = []


__all__ = ("Session",)
