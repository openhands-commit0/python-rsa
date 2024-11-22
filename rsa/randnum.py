"""Functions for generating random numbers."""
import os
import struct
from rsa import common, transform

def read_random_bits(nbits: int) -> bytes:
    """Reads 'nbits' random bits.

    If nbits isn't a whole number of bytes, an extra byte will be appended with
    only the lower bits set.
    """
    nbytes, rbits = divmod(nbits, 8)

    # Get the random bytes
    randomdata = os.urandom(nbytes)

    # Add the remaining random bits
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= (8 - rbits)
        randomdata = bytes([randomvalue]) + randomdata

    return randomdata

def read_random_int(nbits: int) -> int:
    """Reads a random integer of approximately nbits bits."""
    return transform.bytes2int(read_random_bits(nbits))

def read_random_odd_int(nbits: int) -> int:
    """Reads a random odd integer of approximately nbits bits.

    >>> read_random_odd_int(512) & 1
    1
    """
    value = read_random_int(nbits)

    # Make sure it's odd
    return value | 1

def randint(maxvalue: int, minvalue: int=1) -> int:
    """Returns a random integer x with minvalue <= x <= maxvalue

    May take a very long time in specific situations. If maxvalue needs N bits
    to store, the closer maxvalue is to (2 ** N) - 1, the faster this function
    is.
    """
    if minvalue > maxvalue:
        raise ValueError("minvalue must be <= maxvalue")

    # Get the number of bits needed to store maxvalue
    bits_needed = common.bit_size(maxvalue)

    # Keep trying until we find a value
    while True:
        value = read_random_int(bits_needed)
        if minvalue <= value <= maxvalue:
            break

    return value