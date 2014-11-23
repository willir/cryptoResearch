#!/usr/bin/env python3

"""
POC implementation of LBlock Cipher (http://eprint.iacr.org/2011/345.pdf)
"""

s0 = [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5]
s1 = [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3]
s2 = [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10]
s3 = [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1]
s4 = [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3]
s5 = [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5]
s6 = [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2]
s7 = [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6]
s8 = [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3]
s9 = [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6]


def bitstr(n, width=None):
    """return the binary representation of n as a string and
      optionally zero-fill (pad) it to a given length
   """
    result = list()
    while n:
        result.append(str(n % 2))
        n = int(n / 2)
    if (width is not None) and len(result) < width:
        result.extend(['0'] * (width - len(result)))
    result.reverse()
    return ''.join(result)


def mask(n):
    """Return a bitmask of length n (suitable for masking against an
      int to coerce the size to a given length)
   """
    if n >= 0:
        return 2 ** n - 1
    else:
        return 0


def rol(n, rotations=1, width=8):
    """Return a given number of bitwise left rotations of an integer n,
       for a given bit field width.
    """
    rotations %= width
    if rotations < 1:
        return n
    n &= mask(width)  # Should it be an error to truncate here?
    return ((n << rotations) & mask(width)) | (n >> (width - rotations))


def ror(n, rotations=1, width=8):
    """Return a given number of bitwise right rotations of an integer n,
       for a given bit field width.
    """
    rotations %= width
    if rotations < 1:
        return n
    n &= mask(width)
    return (n >> rotations) | ((n << (width - rotations)) & mask(width))


def F(x):
    return s6[(x & 0xf000000) >> 24] << 28 | \
           s4[(x & 0xf0000) >> 16] << 24 | \
           s7[(x & 0xf0000000) >> 28] << 20 | \
           s5[(x & 0xf00000) >> 20] << 16 | \
           s2[(x & 0xf00) >> 8] << 12 | \
           s0[(x & 0xf) >> 0] << 8 | \
           s3[(x & 0xf000) >> 12] << 4 | \
           s1[(x & 0xf0) >> 4] << 0


def keySchedule(K):
    RK = list()
    RK.append((K & (mask(32) << 48)) >> 48)  # 32 left most bits
    for r in range(1, 32):
        K = rol(K, rotations=29, width=80)
        K = (s9[K >> 76] << 76) | (s8[(K >> 72) & 0xf] << 72) | (K & mask(72))
        K ^= r << 46
        RK.append((K & (mask(32) << 48)) >> 48)  # 32 left most bits
    return RK


def Enc(P, RK):
    X1 = (P >> 32) & 0xffffffff
    X0 = P & 0xffffffff

    for r in range(32):
        nextX = F(X1 ^ RK[r]) ^ rol(X0, rotations=8, width=32)
        X0 = X1
        X1 = nextX
    return (X0 << 32) | X1


def Dec(P, RK):
    X0 = (P >> 32) & 0xffffffff
    X1 = P & 0xffffffff

    for r in range(31, -1, -1):
        prevX = ror(F(X0 ^ RK[r]) ^ X1, rotations=8, width=32)
        X1 = X0
        X0 = prevX
    return (X1 << 32) | X0


def encrypt(plain: b'', key: b'') -> b'':
    RK = keySchedule(key)
    return Enc(plain, RK)


def decrypt(cipher: b'', key: b'') -> b'':
    RK = keySchedule(key)
    return Dec(cipher, RK)


if __name__ == '__main__':

    # rKeys = Key_Schedule(0x0123456789abcdeffedc)
    # for rKey in rKeys:
    #     print(hex(rKey))

    key1 = 0x00000000000000000000
    key2 = 0x0123456789abcdeffedc

    enc1 = encrypt(plain=0x0000000000000000, key=key1)
    enc2 = encrypt(plain=0x0123456789abcdef, key=key2)

    dec1 = decrypt(cipher=enc1, key=key1)
    dec2 = decrypt(cipher=enc2, key=key2)

    print(hex(enc1))
    print(hex(enc2))

    print(hex(dec1))
    print(hex(dec2))

    # RK = Key_Schedule(0x0123456789abcdef)
    # print(hex(Enc(0x0123456789abcdef, RK)))
