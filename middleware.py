#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import fileinput
import binascii
import re
import json
import six
import zlib

# Used to find end of the Headers section
EMPTY_LINE = b'\r\n\r\n'


def log(msg):
    """
    Logging to STDERR as STDOUT and STDIN used for data transfer
    @type msg: str or byte string
    @param msg: Message to log to STDERR
    """
    try:
        msg = str(msg) + '\n'
    except:
        pass
    sys.stderr.write(msg)
    sys.stderr.flush()


def find_end_of_headers(byte_data):
    """
    Finds where the header portion ends and the content portion begins.
    @type byte_data: str or byte string
    @param byte_data: Hex decoded req or resp string
    """
    return byte_data.index(EMPTY_LINE) + 4


def safely_load_json_string(json_string):
    try:
        if isinstance(json_string, six.binary_type):
            json_string = json_string.decode('utf-8')
        obj = json.loads(json_string)
        assert isinstance(obj, dict)
    except Exception as e:
        raise APIError('Bad data reconstructing object (%s, %s)' %
                       (type(e).__name__, e))
    return obj


def decompress_gzip(encoded_data):
    try:
        fp = BytesIO(encoded_data)
        try:
            f = GzipFile(fileobj=fp)
            return f.read().decode('utf-8')
        finally:
            f.close()
    except Exception as e:
        # This error should be caught as it suggests that there's a
        # bug somewhere in the client's code.
        # self.log.debug(six.text_type(e), exc_info=True)
        raise APIError('Bad data decoding request (%s, %s)' %
                       (type(e).__name__, e))


def decompress_deflate(encoded_data):
    try:
        return zlib.decompress(encoded_data).decode(encoding='UTF-8')
    except Exception as e:
        # This error should be caught as it suggests that there's a
        # bug somewhere in the client's code.
        # self.log.debug(six.text_type(e), exc_info=True)
        raise APIError('Bad data decoding request (%s, %s)' %
                       (type(e).__name__, e))


def decode_and_decompress_data(encoded_data):
    try:
        try:
            return zlib.decompress(base64.b64decode(encoded_data)).decode('utf-8')
        except zlib.error:
            return base64.b64decode(encoded_data).decode('utf-8')
    except Exception as e:
        # This error should be caught as it suggests that there's a
        # bug somewhere in the client's code.
        # self.log.debug(six.text_type(e), exc_info=True)
        raise APIError('Bad data decoding request (%s, %s)' %
                       (type(e).__name__, e))


def decode_data(encoded_data):
    try:
        return encoded_data.decode('utf-8')
    except UnicodeDecodeError as e:
        # This error should be caught as it suggests that there's a
        # bug somewhere in the client's code.
        # self.log.debug(six.text_type(e), exc_info=True)
        raise APIError('Bad data decoding request (%s, %s)' %
                       (type(e).__name__, e))


def safely_load_json_string(json_string):
    try:
        if isinstance(json_string, six.binary_type):
            json_string = json_string.decode('utf-8')
        obj = json.loads(json_string)
        assert isinstance(obj, dict)
    except Exception as e:
        raise APIError('Bad data reconstructing object (%s, %s)' %
                       (type(e).__name__, e))
    return obj


def process_stdin():
    """
    Process STDIN and output to STDOUT
    """
    for raw_line in fileinput.input():

        line = raw_line.rstrip()

        # Decode base64 encoded line
        decoded = bytes.fromhex(line)

        # Split into metadata and payload, the payload is headers + body
        (raw_metadata, payload) = decoded.split(b'\n', 1)

        # Split into headers and payload
        headers_pos = find_end_of_headers(payload)
        raw_headers = payload[:headers_pos]
        raw_content = payload[headers_pos:]
        log("\n\nBEFORE DECODE\n")
        log(raw_metadata)
        log(raw_headers)
        log(raw_content)
        log(len(raw_content))

        raw_headers = raw_headers.decode('utf-8')
        raw_headers = re.sub(r'POST /api/([0-9]+)/', r'POST /api/1187558/', raw_headers)  # need to add in new proj_id
        # raw_headers = re.sub(r'POST /api/([0-9]+)/store', r'POST /y42lxny4', raw_headers) # need to add in new proj_id
        raw_headers = re.sub(r'&sentry_key=([0-9a-z]+)', r'&sentry_key=024eb6c936654c6ab8482b6a03d31aa6',
                             raw_headers)  # need to add in new proj_id
        content_type = re.search('Content-Type: (.*)\r', raw_headers).group(1)
        if 'Content-Encoding:' in raw_headers:
            content_encoding = re.search('Content-Encoding: (.*)\r', raw_headers).group(1)

        # log('\n\nraw content')
        # log(raw_headers)
        # log(content_type)
        # log(content_encoding)


        if raw_content:  # check if post API?
            if content_type.strip() == "text/plain;charset=UTF-8":
                raw_content = safely_load_json_string(raw_content)  # decoding
            elif content_encoding == 'deflate':
                # log("\n\nINSIDE PYTHON CASE\n")
                # log(raw_headers)
                raw_headers = re.sub(r'sentry_key=([0-9a-z]+)', r'sentry_key=024eb6c936654c6ab8482b6a03d31aa6',
                                     raw_headers)  # need to add in new proj_id
                # log(raw_headers)
                raw_headers = re.sub(r'sentry_secret=([0-9a-z]+)', r'sentry_secret=1225a9a99d744c168a94d6e85a91c214',
                                     raw_headers)  # need to add in new proj_id

                raw_content = decompress_deflate(raw_content)
                # raw_content = zlib.decompress(raw_content).decode(encoding='UTF-8')
                log("\n\nAFTER DECOMPRESS\n")
                log(raw_headers)
                log(raw_content)
                raw_content = safely_load_json_string(raw_content)  # decoding

                log("\n\nAFTER JSON SAFE LOAD\n")
                log(raw_content)



            elif raw_content[0] != b'{':
                raw_content = decode_and_decompress_data(raw_content)

            # raw_content["project"] = "NEW_PROJECT"
            raw_content["project"] = "1187558"
            raw_content = json.dumps(raw_content).encode('utf-8')

            request_type_id = int(raw_metadata.split(b' ')[0])

            # re-encode python body
            if content_encoding == 'deflate':
                log("")

            new_str = 'Content-Length: %s' % len(raw_content)
            raw_headers = re.sub(r'Content-Length: [0-9]+', new_str, raw_headers)

            log("\n\nAFTER REWRITE\n")
            log(raw_metadata)
            log(raw_headers)
            log(raw_content)
            log(len(raw_content))
            raw_headers = raw_headers.encode('utf-8')  # decode back... maybe utf-8?

            log("\n\nAFTER RE-ENCODE\n")
            log(raw_metadata)
            log(raw_headers)
            log(raw_content)

            encoded = binascii.hexlify(raw_metadata + b'\n' + raw_headers + raw_content).decode('ascii')

            log("\n\nFINAL\n")
            log(encoded)

            sys.stdout.write(encoded + '\n')

            log("\nafter stdout\n")


if __name__ == '__main__':
    process_stdin()
