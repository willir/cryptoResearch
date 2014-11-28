#!/usr/bin/env python3

"""
POC implementation of LBlock Cipher (http://eprint.iacr.org/2011/345.pdf)
"""

import sys
import math
import numUtils


sBoxesReal = [
    [14, 9, 15, 0, 13, 4, 10, 11, 1, 2, 8, 3, 7, 6, 12, 5],
    [4, 11, 14, 9, 15, 13, 0, 10, 7, 12, 5, 6, 2, 8, 1, 3],
    [1, 14, 7, 12, 15, 13, 0, 6, 11, 5, 9, 3, 2, 4, 8, 10],
    [7, 6, 8, 11, 0, 15, 3, 14, 9, 10, 12, 13, 5, 2, 4, 1],
    [14, 5, 15, 0, 7, 2, 12, 13, 1, 8, 4, 9, 11, 10, 6, 3],
    [2, 13, 11, 12, 15, 14, 0, 9, 7, 10, 6, 3, 1, 8, 4, 5],
    [11, 9, 4, 14, 0, 15, 10, 13, 6, 12, 5, 7, 3, 8, 1, 2],
    [13, 10, 15, 0, 14, 4, 9, 11, 2, 1, 8, 3, 7, 5, 12, 6],
    [8, 7, 14, 5, 15, 13, 0, 6, 11, 12, 9, 10, 2, 4, 1, 3],
    [11, 5, 15, 0, 7, 2, 9, 13, 4, 8, 1, 12, 14, 10, 3, 6],
]

sBoxesDiff = [[0] + [0xf]*15]*10


def diffS(inD: int) -> int:
    return 0xf if inD != 0 else 0x0;


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

    return '|'.join([''.join(result[i * 4:i * 4 + 4]) for i in range(int(math.ceil(len(result) / 4)))])


# return ''.join(result)


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


def F(x, diffM: bool=False):
    sBoxes = sBoxesReal if not diffM else sBoxesDiff

    lx = numUtils.toArray(x, width=8, reverse=True)

    # SBoxes:
    for i in range(8):
        lx[i] = sBoxes[i][lx[i]]
    #Permutation:
    lx = [lx[1], lx[3], lx[0], lx[2], lx[5], lx[7], lx[4], lx[6]]

    return numUtils.arrToInt(lx, reverse=True)


def keySchedule(K: int, diffM: bool=False):
    sBoxes = sBoxesReal if not diffM else sBoxesDiff

    RK = list()
    RK.append((K & (mask(32) << 48)) >> 48)  # 32 left most bits
    for r in range(1, 32):
        K = rol(K, rotations=29, width=80)
        K = (sBoxes[9][K >> 76] << 76) | (sBoxes[8][(K >> 72) & 0xf] << 72) | (K & mask(72))
        if not diffM:
            K ^= r << 46
        RK.append((K & (mask(32) << 48)) >> 48)  # 32 left most bits
    return RK


def Enc(P, RK, diffM: bool=False, innerStates: list=None, minRound: int=0, maxRound: int=31):
    X1 = (P >> 32) & 0xffffffff
    X0 = P & 0xffffffff

    for r in range(minRound, maxRound + 1):
        nextX = X1 ^ RK[r] if not diffM else X1 | RK[r]
        fRes = F(nextX, diffM=diffM)
        rolled = rol(X0, rotations=8, width=32)
        nextX = fRes ^ rolled if not diffM else fRes | rolled

        if innerStates is not None:
            innerStates.append(X0)
        X0 = X1
        X1 = nextX
    if innerStates is not None:
        innerStates.append(X0)
        innerStates.append(X1)
    return (X0 << 32) | X1


def Dec(P, RK):
    X0 = (P >> 32) & 0xffffffff
    X1 = P & 0xffffffff

    for r in range(31, -1, -1):
        prevX = ror(F(X0 ^ RK[r]) ^ X1, rotations=8, width=32)
        X1 = X0
        X0 = prevX
    return (X1 << 32) | X0


def encrypt(plain: int, key: int) -> int:
    RK = keySchedule(key)
    return Enc(plain, RK)


def decrypt(cipher: int, key: int) -> int:
    RK = keySchedule(key)
    return Dec(cipher, RK)


def showKeyDiff():

    mKeyDiff = 0xf << 75
    rKeyDiff = keySchedule(mKeyDiff, diffM=True)

    for r in range(32):
        print(str(r) + ':' + bitstr(rKeyDiff[r], width=32))


def showInnerStateDiff(pDiff: int, keyDiff: int, startRound: int=0, stopRound: int=32):
    rKeyDiff = keySchedule(keyDiff, diffM=True)
    innerStates = []
    Enc(P=pDiff, RK=rKeyDiff, diffM=True, innerStates=innerStates, minRound=startRound, maxRound=stopRound)

    print(len(innerStates))

    for r in range(len(innerStates)):
        print(str(r + startRound - 1) + ':' + bitstr(innerStates[r], width=32))



if __name__ == '__main__':

#    showKeyDiff()
    showInnerStateDiff(pDiff=0x0, keyDiff=0xf << 75, startRound=8, stopRound=20)
    sys.exit(0)

    key1 = 0x00000000000000000000
    key2 = 0x0123456789abcdeffedc

    enc2 = encrypt(plain=0x0123456789abcdef, key=key2)
    enc1 = encrypt(plain=0x0000000000000000, key=key1)

    dec1 = decrypt(cipher=enc1, key=key1)
    dec2 = decrypt(cipher=enc2, key=key2)

    print(hex(enc1))
    print(hex(enc2))

    print(hex(dec1))
    print(hex(dec2))

    # RK = Key_Schedule(0x0123456789abcdef)
    # print(hex(Enc(0x0123456789abcdef, RK)))
