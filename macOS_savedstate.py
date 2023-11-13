'''
parse SavedState artifacts extracted from OSX.

author: Willi Ballenthin (william.ballenthin@fireeye.com)
license: Apache 2.0
'''
import re
import sys
import json
import struct
import logging
import binascii
import collections

logger = logging.getLogger('osx.savedstate')
logging.basicConfig(level=logging.INFO)

try:
    import hexdump
except ImportError:
    logger.error('please install `hexdump` via pip')
    sys.exit(-1)

try:
    import zbplist as bplist
except ImportError:
    logger.error('zbplist.py not found in the same directory')
    sys.exit(-1)
except SyntaxError:
    logger.error('python3 required')
    sys.exit(-1)


def aes_decrypt(key, ciphertext, iv=b'\x00' * 0x10):
    # AES128-CBC

    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.ciphers
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    backend = cryptography.hazmat.backends.default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


WindowState = collections.namedtuple('WindowState',
                                     [
                                         # size of the byte array in `data.data` for this window.
                                         'size',
                                         # the parsed metadata associated with this window from `windows.plist`
                                         'meta',
                                         # the decrypted window state byte array.
                                         'plaintext',
                                         # the deserialized NSKeyedArchiver window state.
                                         'state'
                                     ])


def parse_plaintext(buf):
    '''
    parse the decrypted window state extracted from `data.data`.

    args:
      buf (bytes): the decrypted window state byte array.

    returns:
      Dict[any: any]: the deserialized bplist contents.
    '''
    # layout:
    #
    #   struct S {
    #      // often 0x0
    #      uint32_t unk1;
    #      uint32_t class_name_size;
    #      char     class_name[magic_size];
    #      // seems to be "rchv"
    #      char     magic[4];
    #      uint32_t size;
    #      // this is an NSKeyedArchiver serialized datastructure.
    #      // in practice, a bplist with specific interpretation.
    #      uint8_t  buf[size];
    #   }
    unk1, class_name_size = struct.unpack_from('>II', buf, 0x0)
    class_name, magic, size = struct.unpack_from('>%ds4sI' % (class_name_size), buf, 8)
    if magic != b'rchv':
        raise ValueError('unexpected magic')

    class_name = class_name.decode('ascii')
    logger.debug('found archived class: %s', class_name)

    header_size = 8 + class_name_size + 8

    plistbuf = buf[header_size:header_size + size]
    return bplist.loads(plistbuf)


def parse_window_state(plist, buf):
    magic, version, window_id, size = struct.unpack_from('>4s4sII', buf, 0x0)
    if magic != b'NSCR':
        raise ValueError('invalid magic')

    if version != b'1000':
        raise ValueError('invalid version')

    ciphertext = buf[0x10:size]

    try:
        window = [d for d in plist if d.get('NSWindowID') == window_id][0]
    except IndexError:
        window_ids = ', '.join(list(sorted(map(lambda p: str(p.get('NSWindowID', 'unknown')), plist))))
        raise ValueError('missing window metadata, wanted: %d, found: %s' % (window_id, window_ids), size)
    else:
        logger.debug('found window: %d', window_id)

    plaintext = aes_decrypt(window['NSDataKey'], ciphertext)
    state = parse_plaintext(plaintext)

    return WindowState(size, window, plaintext, state)


def parse_window_states(plist, data):
    '''
    decrypt and parse the serialized window state stored in `data.data` and `windows.plist`.

    args:
      plist (Dict[any, any]): parsed plist `windows.plist`.
      data (bytes): the contents of `data.data`.

    returns:
      List[WindowState]: decrypted window state instances, with fields:
        size (int): the size of the window state blob.
        meta (Dict[any, any]): the relevant metadata from `windows.plist`.
        plaintext (bytes): the decrypted windows state structure.
        state (Dict[any, any]): the deserialized window state.
    '''
    buf = data

    while len(buf) > 0x10:
        if not buf.startswith(b'NSCR'):
            raise ValueError('invalid magic')

        try:
            window_state = parse_window_state(plist, buf)
        except ValueError as e:
            logger.warning('failed to parse window state: %s', e.args[0])
            if len(e.args) > 1:
                size = e.args[1]
                buf = buf[size:]
                continue
            else:
                break

        buf = buf[window_state.size:]
        yield window_state


def json_encode_window_state(z):
    '''
    helper for this tool to serialize custom classes into json.
    '''
    if isinstance(z, bplist.UID):
        # this is just a number
        return z.data

    if isinstance(z, bytes):
        try:
            # much of the data is text, so try to fetch that
            return z.decode('utf-8')
        except UnicodeDecodeError:
            # otherwise, return hex, with a tag
            return 'hex://' + binascii.b2a_hex(z).decode('ascii')
    else:
        type_name = z.__class__.__name__
        raise TypeError("Object of type '{type_name}' is not JSON serializable".format(**locals()))


def main():
    import os
    import os.path

    inputpath = sys.argv[1]
    outputpath = sys.argv[2]

    logger.info('input: %s', inputpath)

    with open(os.path.join(inputpath, 'windows.plist'), 'rb') as f:
        windows = bplist.load(f)

    with open(os.path.join(inputpath, 'data.data'), 'rb') as f:
        data = f.read()

    for i, window in enumerate(parse_window_states(windows, data)):
        if not window.meta:
            logger.info('no data for window%d', i)
            continue

        filename = 'window%d' % (i)
        filepath = os.path.join(outputpath, filename + '.json')
        logger.info('writing: %s', filepath)
        with open(filepath, 'wb') as f:
            doc = json.dumps({'meta': window.meta,
                              'state': window.state},
                              default=json_encode_window_state,
                              indent=4,
                              sort_keys=True)
            f.write(doc.encode('utf-8'))


if __name__ == '__main__':
    main()
