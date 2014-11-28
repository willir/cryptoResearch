#!/usr/bin/env python3


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
