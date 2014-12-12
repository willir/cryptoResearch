#!/usr/bin/env python3

"""
POC implementation of LBlock Cipher (http://eprint.iacr.org/2011/345.pdf)
"""
from builtins import reversed
import os
import sys

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
sBoxesDiff = [[0] + [0xf] * 15] * 10

permTable = [1, 3, 0, 2, 5, 7, 4, 6]  # [2, 0, 3, 1, 6, 4, 7, 5]
reversePermTable = numUtils.reversePermutation(permTable)


class KeyDiffRes: pass
class SBoxesUsed: pass


class SBoxesUsed:
    data = None
    startRound = -1
    weight = -1

    def __init__(self, startRound):
        self.data = []
        self.startRound = startRound

    def append(self, sBox: list):
        if not isinstance(sBox, list):
            raise TypeError('type(sBox):%s have to be list', str(type(sBox)))
        self.data.append(sBox)

    def getWeight(self):
        if self.weight >= 0:
            return self.weight

        if not self.data:
            sys.exit('self.data is empty')
        if len(self.data[0]) != 8:
            sys.exit('len(self.sBoxesUsed):%s != 8' % len(self.data[0]))

        self.weight = sum(map(lambda el: el.count(1), self.data))
        return self.weight

    def reverse(self):
        self.data.reverse()

    def cmp(self, other: SBoxesUsed) -> int:
        return self.getWeight() - other.getWeight()

    def __str__(self):
        res = ''
        res += '%d %s\n' % (self.getWeight(), 'SBoxes:')
        for r in range(len(self.data)):
            res += '%s : %s\n' % (str(r + self.startRound).zfill(2), '|'.join(map(str, self.data[r])))
        return res

    def __eq__(self, other: SBoxesUsed):
        return self.cmp(other) == 0

    def __lt__(self, other: SBoxesUsed):
        return self.cmp(other) < 0


class KeyDiffRes:
    startRound = -1
    stopRound = -1
    mKeyDiff = -1
    rKeyDiff = None
    innerStates = None
    sBoxesUsed = None

    def __init__(self, startRound: int, stopRound: int, mKeyDiff: int, rKeyDiff: list, innerStates: list,
                 sBoxesUsed: SBoxesUsed):
        self.startRound = startRound
        self.stopRound = stopRound
        self.mKeyDiff = mKeyDiff
        self.rKeyDiff = rKeyDiff
        self.innerStates = innerStates
        self.sBoxesUsed = sBoxesUsed

    def getMKeyShift(self):
        num = self.mKeyDiff
        shift = 0
        while (num & 1) == 0:
            shift += 1
            num >>= 1
        return shift

    def cmp(self, other: KeyDiffRes) -> int:
        return self.sBoxesUsed.cmp(other.sBoxesUsed)

    def __eq__(self, other: KeyDiffRes):
        return self.cmp(other) == 0

    def __lt__(self, other: KeyDiffRes):
        return self.cmp(other) < 0


def diffS(inD: int) -> int:
    return 0xf if inD != 0 else 0x0


def F(x, diffM: bool=False, sBoxesUsed: SBoxesUsed=None):
    sBoxes = sBoxesReal if not diffM else sBoxesDiff

    lx = numUtils.toArray(x, width=8, reverse=True)

    # SBoxes:
    for i in range(8):
        lx[i] = sBoxes[i][lx[i]]

    if sBoxesUsed is not None:
        sBoxesUsed.append(list(map(lambda num: 1 if num != 0 else 0, reversed(lx))))

    # Permutation:
    lx = numUtils.doPermutation(lx, permTable)

    return numUtils.arrToInt(lx, reverse=True)


def reverseF(x: int, xPrev: int) -> (int, list):
    """
    Computes reverse F for computing sboxes which are used for getting specific output nibbles.
    :param x: x[r]
    :param xPrev: x[r-1]
    :return: (x, sBoxesUsed)
    """
    perm = numUtils.toArray(x, width=8, reverse=True)
    sBoxesUsed = numUtils.doPermutation(perm, reversePermTable)

    sBoxesUsed.reverse()
    newX = xPrev | numUtils.arrToInt(sBoxesUsed, reverse=False)
    return (newX, list(map(lambda x: 1 if x > 0 else 0, sBoxesUsed)))


def keySchedule(K: int, diffM: bool=False):
    sBoxes = sBoxesReal if not diffM else sBoxesDiff

    RK = list()
    RK.append((K & (numUtils.mask(32) << 48)) >> 48)  # 32 left most bits
    for r in range(1, 32):
        K = numUtils.rol(K, rotations=29, width=80)
        K = (sBoxes[9][K >> 76] << 76) | (sBoxes[8][(K >> 72) & 0xf] << 72) | (K & numUtils.mask(72))
        if not diffM:
            K ^= r << 46
        RK.append((K & (numUtils.mask(32) << 48)) >> 48)  # 32 left most bits
    return RK


def Enc(P, RK, diffM: bool=False, minRound: int=0, maxRound: int=31, innerStates: list=None,
        sBoxesUsed: SBoxesUsed=None):
    X1 = (P >> 32) & 0xffffffff
    X0 = P & 0xffffffff

    for r in range(minRound, maxRound + 1):
        nextX = X1 ^ RK[r] if not diffM else X1 | RK[r]
        fRes = F(nextX, diffM=diffM, sBoxesUsed=sBoxesUsed)
        rolled = numUtils.rol(X0, rotations=8, width=32)
        nextX = fRes ^ rolled if not diffM else fRes | rolled

        if innerStates is not None:
            innerStates.append(X0)
        X0 = X1
        X1 = nextX
    if innerStates is not None:
        innerStates.append(X0)
        innerStates.append(X1)
    return (X0 << 32) | X1


def Dec(P, RK, diffM: bool=False, minRound: int=0, maxRound: int=31, innerStates: list=None,
        sBoxesUsed: SBoxesUsed=None):
    X0 = (P >> 32) & 0xffffffff
    X1 = P & 0xffffffff

    if minRound > maxRound:
        raise ValueError("minRound:%d > maxRound:%d" % (minRound, maxRound))

    xorFunc = (lambda x, y: x ^ y) if not diffM else (lambda a, b: a | b)

    for r in range(maxRound, minRound - 1, -1):
        fRes = F(xorFunc(X0, RK[r]), diffM=diffM, sBoxesUsed=sBoxesUsed)
        fRes = xorFunc(fRes, X1)
        prevX = numUtils.ror(fRes, rotations=8, width=32)

        if innerStates is not None:
            innerStates.append(X1)
        X1 = X0
        X0 = prevX
    if innerStates is not None:
        innerStates.append(X1)
        innerStates.append(X0)
        innerStates.reverse()
    if sBoxesUsed:
        sBoxesUsed.reverse()

    return (X1 << 32) | X0


def reverseEnc(P, rounds: int=31, innerStates: list=None, sBoxesUsed: SBoxesUsed=None):
    X1 = (P >> 32) & 0xffffffff
    X0 = P & 0xffffffff

    innerStates.append(X1)

    for r in range(rounds):
        (xPrev, curSBoxes) = reverseF(X1, X0)

        X0 = numUtils.ror(X1, rotations=8, width=32)
        X1 = xPrev

        sBoxesUsed.append(curSBoxes)
        innerStates.append(X1)

    innerStates.reverse()
    sBoxesUsed.reverse()


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
        print(str(r) + ':' + numUtils.bitstr(rKeyDiff[r], width=32))


def showInnerStateDiff(pDiff: int, keyDiff: int, startRound: int=0, stopRound: int=32):
    rKeyDiff = keySchedule(keyDiff, diffM=True)
    innerStates = []
    if startRound > stopRound:
        method = Dec
        startRound, stopRound = stopRound, startRound
    else:
        method = Enc

    sBoxesUsed = SBoxesUsed(startRound=startRound)

    method(P=pDiff, RK=rKeyDiff, diffM=True, innerStates=innerStates, minRound=startRound, maxRound=stopRound,
           sBoxesUsed=sBoxesUsed)

    print(len(innerStates), 'InnerStates:')
    for r in range(len(innerStates)):
        print(str(r + startRound - 1).zfill(2) + ':' + numUtils.bitstr(innerStates[r], width=32))

    print(sBoxesUsed)

    sBoxesReverse = SBoxesUsed(startRound=startRound)
    innerStatesReverse = []
    reverseEnc(0xf << 20 | 0xf, rounds=8, innerStates=innerStatesReverse, sBoxesUsed=sBoxesReverse)

    print(len(innerStatesReverse), 'InnerStatesReverse:')
    for r in range(len(innerStatesReverse)):
        print(str(r + startRound - 1).zfill(2) + ':' + numUtils.bitstr(innerStatesReverse[r], width=32))

    print(sBoxesReverse)


def getMintDiff(pDiff: int, startRound: int=0, stopRound: int=32):
    res = []
    method = Enc if startRound < stopRound else Dec
    for shift in range(80 - 4 + 1):
        keyDiff = 0xf << shift
        rKeyDiff = keySchedule(keyDiff, diffM=True)
        innerStates = []
        sBoxesUsed = SBoxesUsed(startRound=startRound)
        method(P=pDiff, RK=rKeyDiff, diffM=True, innerStates=innerStates, minRound=startRound, maxRound=stopRound,
               sBoxesUsed=sBoxesUsed)

        res.append(KeyDiffRes(startRound=startRound, stopRound=stopRound, mKeyDiff=keyDiff, rKeyDiff=rKeyDiff,
                              innerStates=innerStates, sBoxesUsed=sBoxesUsed))

    res.sort()

    for i in range(len(res)):
        if i != 0:
            print('**************************************************************\n\n')
        print('--- %d ---' % i)
        print(res[i].getMKeyShift(), numUtils.bitstr(res[i].mKeyDiff, width=80))
        print(res[i].sBoxesUsed)


if __name__ == '__main__':
    # showKeyDiff()
    showInnerStateDiff(pDiff=0x0, keyDiff=0xf << 75, startRound=8, stopRound=19) # Forward matching
#    showInnerStateDiff(pDiff=0x0, keyDiff=0xf << 75, startRound=31, stopRound=20)
    #    getMintDiff(pDiff=0x0, startRound=0, stopRound=7)
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
