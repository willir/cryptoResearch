#!/usr/bin/env python3
import math


def toArray(num: int, width: int=0, reverse: bool=False):
    res = []
    while num > 0:
        res.append(num & 0xf)
        num >>= 4
    if len(res) < width:
        res.extend([0] * (width-len(res)))
    if not reverse:
        res.reverse()
    return res


def arrToInt(arr: list, reverse: bool=False):
    res = 0
    if reverse:
        arr = reversed(arr)
    for nibble in arr:
        res <<= 4
        res |= nibble
    return res


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

