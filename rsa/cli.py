"""Commandline scripts.

These scripts are called by the executables defined in setup.py.
"""
import abc
import sys
import typing
import optparse
import rsa
import rsa.key
import rsa.pkcs1
HASH_METHODS = sorted(rsa.pkcs1.HASH_METHODS.keys())
Indexable = typing.Union[typing.Tuple, typing.List[str]]

def keygen() -> None:
    """Key generator."""
    pass

class CryptoOperation(metaclass=abc.ABCMeta):
    """CLI callable that operates with input, output, and a key."""
    keyname = 'public'
    usage = 'usage: %%prog [options] %(keyname)s_key'
    description = ''
    operation = 'decrypt'
    operation_past = 'decrypted'
    operation_progressive = 'decrypting'
    input_help = 'Name of the file to %(operation)s. Reads from stdin if not specified.'
    output_help = 'Name of the file to write the %(operation_past)s file to. Written to stdout if this option is not present.'
    expected_cli_args = 1
    has_output = True
    key_class = rsa.PublicKey

    def __init__(self) -> None:
        self.usage = self.usage % self.__class__.__dict__
        self.input_help = self.input_help % self.__class__.__dict__
        self.output_help = self.output_help % self.__class__.__dict__

    @abc.abstractmethod
    def perform_operation(self, indata: bytes, key: rsa.key.AbstractKey, cli_args: Indexable) -> typing.Any:
        """Performs the program's operation.

        Implement in a subclass.

        :returns: the data to write to the output.
        """
        pass

    def __call__(self) -> None:
        """Runs the program."""
        cli, cli_args = self.parse_cli()
        key = self.read_key(cli_args[0], cli.keyform)
        indata = self.read_infile(cli.input)
        print(self.operation_progressive.title(), file=sys.stderr)
        outdata = self.perform_operation(indata, key, cli_args)
        if self.has_output:
            self.write_outfile(outdata, cli.output)

    def parse_cli(self) -> typing.Tuple[optparse.Values, typing.List[str]]:
        """Parse the CLI options

        :returns: (cli_opts, cli_args)
        """
        pass

    def read_key(self, filename: str, keyform: str) -> rsa.key.AbstractKey:
        """Reads a public or private key."""
        pass

    def read_infile(self, inname: str) -> bytes:
        """Read the input file"""
        pass

    def write_outfile(self, outdata: bytes, outname: str) -> None:
        """Write the output file"""
        pass

class EncryptOperation(CryptoOperation):
    """Encrypts a file."""
    keyname = 'public'
    description = 'Encrypts a file. The file must be shorter than the key length in order to be encrypted.'
    operation = 'encrypt'
    operation_past = 'encrypted'
    operation_progressive = 'encrypting'

    def perform_operation(self, indata: bytes, pub_key: rsa.key.AbstractKey, cli_args: Indexable=()) -> bytes:
        """Encrypts files."""
        pass

class DecryptOperation(CryptoOperation):
    """Decrypts a file."""
    keyname = 'private'
    description = 'Decrypts a file. The original file must be shorter than the key length in order to have been encrypted.'
    operation = 'decrypt'
    operation_past = 'decrypted'
    operation_progressive = 'decrypting'
    key_class = rsa.PrivateKey

    def perform_operation(self, indata: bytes, priv_key: rsa.key.AbstractKey, cli_args: Indexable=()) -> bytes:
        """Decrypts files."""
        pass

class SignOperation(CryptoOperation):
    """Signs a file."""
    keyname = 'private'
    usage = 'usage: %%prog [options] private_key hash_method'
    description = 'Signs a file, outputs the signature. Choose the hash method from %s' % ', '.join(HASH_METHODS)
    operation = 'sign'
    operation_past = 'signature'
    operation_progressive = 'Signing'
    key_class = rsa.PrivateKey
    expected_cli_args = 2
    output_help = 'Name of the file to write the signature to. Written to stdout if this option is not present.'

    def perform_operation(self, indata: bytes, priv_key: rsa.key.AbstractKey, cli_args: Indexable) -> bytes:
        """Signs files."""
        pass

class VerifyOperation(CryptoOperation):
    """Verify a signature."""
    keyname = 'public'
    usage = 'usage: %%prog [options] public_key signature_file'
    description = 'Verifies a signature, exits with status 0 upon success, prints an error message and exits with status 1 upon error.'
    operation = 'verify'
    operation_past = 'verified'
    operation_progressive = 'Verifying'
    key_class = rsa.PublicKey
    expected_cli_args = 2
    has_output = False

    def perform_operation(self, indata: bytes, pub_key: rsa.key.AbstractKey, cli_args: Indexable) -> None:
        """Verifies files."""
        pass
encrypt = EncryptOperation()
decrypt = DecryptOperation()
sign = SignOperation()
verify = VerifyOperation()