"""Data transformation functions.

From bytes to a number, number to bytes, etc.
"""
import math

def bytes2int(raw_bytes: bytes) -> int:
    """Converts a list of bytes or an 8-bit string to an integer.

    When using unicode strings, encode it to some encoding like UTF8 first.

    >>> (((128 * 256) + 64) * 256) + 15
    8405007
    >>> bytes2int(b'\\x80@\\x0f')
    8405007

    """
    return int.from_bytes(raw_bytes, byteorder='big')

def int2bytes(number: int, fill_size: int=0) -> bytes:
    """
    Convert an unsigned integer to bytes (big-endian)::

    Does not preserve leading zeros if you don't specify a fill size.

    :param number:
        Integer value
    :param fill_size:
        If the optional fill size is given the length of the resulting
        byte string is expected to be the fill size and will be padded
        with prefix zero bytes to satisfy that length.
    :returns:
        Raw bytes (base-256 representation).
    :raises:
        ``OverflowError`` when fill_size is given and the number takes up more
        bytes than fit into the block. This requires the ``overflow``
        argument to this function to be set to ``False`` otherwise, no
        error will be raised.
    """
    if not isinstance(number, int):
        raise TypeError("Number must be an integer")
    if number < 0:
        raise ValueError("Number must be an unsigned integer")

    # Calculate the number of bytes needed to represent the integer
    bytes_needed = max(1, math.ceil(number.bit_length() / 8))

    # If fill_size is given, check if the number fits
    if fill_size > 0:
        if bytes_needed > fill_size:
            raise OverflowError("Number is too large for the given fill_size")
        bytes_needed = fill_size

    return number.to_bytes(bytes_needed, byteorder='big')
if __name__ == '__main__':
    import doctest
    doctest.testmod()