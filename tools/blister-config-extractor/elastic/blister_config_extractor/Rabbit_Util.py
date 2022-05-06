def ROTL8(v, n):
    return ((v << n) & 0xFF) | ((v >> (8 - n)) & 0xFF)


def ROTL16(v, n):
    return ((v << n) & 0xFFFF) | ((v >> (16 - n)) & 0xFFFF)


def ROTL32(v, n):
    return ((v << n) & 0xFFFFFFFF) | ((v >> (32 - n)) & 0xFFFFFFFF)


def ROTL64(v, n):
    return ((v << n) & 0xFFFFFFFFFFFFFFFF) | ((v >> (64 - n)) & 0xFFFFFFFFFFFFFFFF)


def ROTR8(v, n):
    return ROTL8(v, 8 - n)


def ROTR16(v, n):
    return ROTL16(v, 16 - n)


def ROTR32(v, n):
    return ROTL32(v, 32 - n)


def ROTR64(v, n):
    return ROTL64(v, 64 - n)


def SWAP32(v):
    return (ROTL32(v, 8) & 0x00FF00FF) | (ROTL32(v, 24) & 0xFF00FF00)


class Rabbit_state(object):
    def __init__(self):
        self.x = [0] * 8
        self.c = [0] * 8
        self.carry = 0


class Rabbit_ctx(object):
    def __init__(self):
        self.m = Rabbit_state()
        self.w = Rabbit_state()
