"""Functions that load and write PEM-encoded files."""
import base64
import typing
FlexiText = typing.Union[str, bytes]

def _markers(pem_marker: FlexiText) -> typing.Tuple[bytes, bytes]:
    """
    Returns the start and end PEM markers, as bytes.
    """
    if isinstance(pem_marker, str):
        pem_marker = pem_marker.encode('ascii')

    return (
        b'-----BEGIN ' + pem_marker + b'-----',
        b'-----END ' + pem_marker + b'-----'
    )

def _pem_lines(contents: bytes, pem_start: bytes, pem_end: bytes) -> typing.Iterator[bytes]:
    """Generator over PEM lines between pem_start and pem_end."""
    in_pem_part = False
    seen_pem_start = False

    for line in contents.splitlines():
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Handle start marker
        if line == pem_start:
            if in_pem_part:
                raise ValueError('Seen start marker "%s" twice' % pem_start)

            in_pem_part = True
            seen_pem_start = True
            continue

        # Skip stuff before first marker
        if not in_pem_part:
            continue

        # Handle end marker
        if line == pem_end:
            in_pem_part = False
            break

        # Skip stuff after end marker
        if not in_pem_part:
            continue

        # Load the base64 data
        yield line

    if not seen_pem_start:
        raise ValueError('No PEM start marker "%s" found' % pem_start)

    if in_pem_part:
        raise ValueError('No PEM end marker "%s" found' % pem_end)

def load_pem(contents: FlexiText, pem_marker: FlexiText) -> bytes:
    """Loads a PEM file.

    :param contents: the contents of the file to interpret
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-decoded content between the start and end markers.

    @raise ValueError: when the content is invalid, for example when the start
        marker cannot be found.

    """
    # Convert strings to bytes
    if isinstance(contents, str):
        contents = contents.encode('ascii')

    # Get the start and end markers
    pem_start, pem_end = _markers(pem_marker)

    # Get all lines between the markers
    pem_lines = [line for line in _pem_lines(contents, pem_start, pem_end)]

    # Base64-decode the contents
    pem = b''.join(pem_lines)
    return base64.standard_b64decode(pem)

def save_pem(contents: bytes, pem_marker: FlexiText) -> bytes:
    """Saves a PEM file.

    :param contents: the contents to encode in PEM format
    :param pem_marker: the marker of the PEM content, such as 'RSA PRIVATE KEY'
        when your file has '-----BEGIN RSA PRIVATE KEY-----' and
        '-----END RSA PRIVATE KEY-----' markers.

    :return: the base64-encoded content between the start and end markers, as bytes.

    """
    # Get the start and end markers
    pem_start, pem_end = _markers(pem_marker)

    # Base64-encode the contents
    b64 = base64.standard_b64encode(contents).replace(b'\n', b'')

    # Split into lines of 64 characters each
    chunks = [b64[i:i + 64] for i in range(0, len(b64), 64)]

    # Create output
    lines = [pem_start, b''] + chunks + [b'', pem_end]

    # Combine all lines
    return b'\n'.join(lines)