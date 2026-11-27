#!/usr/bin/env python3
"""Generate inert header MODELS in checksum-correct SYNTHETIC HTTP/TCP PCAPs.

No specimens, executable code, native captures, external files or downloads.
The PE objects model selected header constraints, not loader-valid programs.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import zipfile

EPOCH = 1700000000
CLIENT, SERVER = '192.0.2.10', '198.51.100.20'


def pe_model(arch='x86', overlay=0):
    machine, magic, optional = {'x86': (0x14c, 0x10b, 224),
                                'x64': (0x8664, 0x20b, 240),
                                'arm64': (0xaa64, 0x20b, 240)}[arch]
    data = bytearray(1024 + overlay)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<HH', data, 132, machine, 1)
    struct.pack_into('<H', data, 148, optional)
    struct.pack_into('<H', data, 152, magic)
    struct.pack_into('<I', data, 152 + 36, 512)  # FileAlignment
    struct.pack_into('<I', data, 152 + 60, 512)  # SizeOfHeaders
    fixed = 96 if arch == 'x86' else 112
    struct.pack_into('<I', data, 152 + fixed - 4, 16)
    section = 152 + optional
    data[section:section + 8] = b'.model\0\0'
    struct.pack_into('<II', data, section + 16, 512, 512)
    # No entry point, executable section characteristics, instructions or DOS stub.
    return bytes(data)


def cases():
    base = pe_model()
    result = []

    def add(label, notice=False, name='report.pdf', body=base, cd=None,
            extra=(), status=200, request_extra=(), uri='/object', declared=None,
            chunked=False):
        if cd is None:
            cd = [('Content-Disposition', f'attachment; filename="{name}"'.encode())]
        headers = list(cd) + list(extra)
        if chunked:
            headers.append(('Transfer-Encoding', b'chunked'))
        else:
            headers.append(('Content-Length', str(len(body) if declared is None else declared).encode()))
        if not any(k.lower() == 'content-type' for k, _ in headers):
            headers.append(('Content-Type', b'application/octet-stream'))
        result.append(dict(id=label, notice=notice, filename=name if notice else '',
                           format='PE32+' if label in ('pe-x64', 'pe-arm64') else 'PE32',
                           body=body, headers=headers, status=status, uri=uri,
                           request_extra=request_extra, chunked=chunked))

    add('pe-x86', True)
    add('pe-x64', True, body=pe_model('x64'))
    add('pe-arm64', True, body=pe_model('arm64'))
    for label, fallback in [('extended-empty', b''), ('extended-path', b'../setup.exe'),
                            ('extended-legacy', b'caf\xe9.exe')]:
        add(label, True, cd=[('Content-Disposition', b'attachment; filename="' + fallback + b'"; filename*=UTF-8\'\'report.pdf')])
    add('extended-reverse', True, cd=[('Content-Disposition', b'attachment; filename*=UTF-8\'\'report.pdf; filename=""')])
    for label, value in [
        ('invalid-active-utf8', b'attachment; filename="report.pdf"; filename*=UTF-8\'\'%FF.pdf'),
        ('invalid-active-language', b'attachment; filename="report.pdf"; filename*=UTF-8\'--\'report.pdf'),
        ('duplicate-parameter', b'attachment; filename="report.pdf"; filename="other.pdf"'),
        ('path-selected', b'attachment; filename="report.pdf"; filename*=UTF-8\'\'..%2Freport.pdf'),
        ('unsupported-charset', b'attachment; filename="report.pdf"; filename*=ISO-8859-1\'\'report.pdf'),
        ('unknown-disposition', b'unknown; filename="report.pdf"')]:
        add(label, cd=[('Content-Disposition', value)])
    bad = bytearray(base)
    bad[128:132] = b'PX\0\0'
    add('bad-pe-signature', body=bytes(bad))
    bad = bytearray(base)
    struct.pack_into('<I', bad, 152 + 224 + 16, 1024)
    add('raw-section-past-eof', body=bytes(bad))
    add('honest-exe', name='program.exe')
    add('honest-dll', name='library.dll')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
        info = zipfile.ZipInfo('report.pdf', date_time=(2020, 1, 1, 0, 0, 0))
        z.writestr(info, base)
    add('outer-zip', body=archive.getvalue())
    add('non-pe-data', body=b'%PDF-1.7\nINERT MODEL CONTROL\n' + bytes(996))
    add('short-body-vs-content-length', declared=len(base) + 100)
    add('range-response', status=206, extra=[('Content-Range', b'bytes 0-1023/1024')],
        request_extra=[('Range', b'bytes=0-1023')])
    add('chunked', chunked=True)
    add('content-type-name-poison', cd=[], extra=[('Content-Type', b'application/octet-stream; name="report.pdf"')])
    add('uri-only', cd=[], uri='/report.pdf')
    add('duplicate-disposition', extra=[('Content-Disposition', b'attachment; filename="other.pdf"')])
    add('duplicate-content-length', extra=[('Content-Length', b'1024')])
    add('identity-encoding', True, extra=[('Content-Encoding', b'identity')])
    add('long-overlay', True, body=pe_model(overlay=1024 * 1024))
    return result


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def pcap(case):
    packets = []
    cseq, sseq = 1000, 9000

    def packet(origin, flags, payload=b''):
        nonlocal cseq, sseq
        src, dst = (CLIENT, SERVER) if origin else (SERVER, CLIENT)
        sport, dport = (41000, 80) if origin else (80, 41000)
        seq, ack = (cseq, sseq) if origin else (sseq, cseq)
        if flags == 2:
            ack = 0
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        check = checksum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', check) + tcp[18:] + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), len(packets) + 1,
                         0x4000, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
        ethernet = bytes.fromhex('0200000000020200000000010800')
        packets.append(ethernet + ip + tcp)
        advance = len(payload) + bool(flags & 2) + bool(flags & 1)
        if origin:
            cseq += advance
        else:
            sseq += advance

    packet(True, 2)
    packet(False, 18)
    packet(True, 16)
    request = f'GET {case["uri"]} HTTP/1.1\r\nHost: synthetic.invalid\r\nConnection: close\r\n'.encode()
    for key, value in case['request_extra']:
        request += key.encode() + b': ' + value + b'\r\n'
    packet(True, 24, request + b'\r\n')
    packet(False, 16)
    response = f'HTTP/1.1 {case["status"]} Model\r\nConnection: close\r\n'.encode()
    for key, value in case['headers']:
        response += key.encode() + b': ' + value + b'\r\n'
    packet(False, 24, response + b'\r\n')
    packet(True, 16)
    body = case['body']
    if case['chunked']:
        body = f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
    for start in range(0, len(body), 1024):
        packet(False, 24, body[start:start + 1024])
        packet(True, 16)
    packet(False, 17)
    packet(True, 16)
    packet(True, 17)
    packet(False, 16)
    out = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, data in enumerate(packets):
        micros = i * 1000
        out.extend(struct.pack('<IIII', EPOCH + micros // 1000000, micros % 1000000, len(data), len(data)))
        out.extend(data)
    return bytes(out)


def generate(output):
    output = Path(output).resolve()
    repository = Path(__file__).resolve().parents[2]
    if output == repository or repository in output.parents:
        raise ValueError('Output must be outside the repository')
    output.mkdir(parents=True, exist_ok=False)
    manifest = []
    for case in cases():
        data = pcap(case)
        path = output / (case['id'] + '.pcap')
        path.write_bytes(data)
        timing_offset = 24
        completion_min = EPOCH
        end = EPOCH
        while timing_offset < len(data):
            sec, usec, length, _ = struct.unpack_from('<IIII', data, timing_offset)
            packet = data[timing_offset + 16:timing_offset + 16 + length]
            end = sec + usec / 1000000
            if packet[26:30] == socket.inet_aton(SERVER) and len(packet) > 54:
                completion_min = end
            timing_offset += 16 + length
        manifest.append(dict(id=case['id'], notice=case['notice'], filename_hex=case['filename'].encode().hex(),
                             format=case['format'], body_bytes=len(case['body']),
                             pcap_sha256=hashlib.sha256(data).hexdigest(),
                             provenance='synthetic TCP/HTTP carrying inert header model',
                             start=EPOCH, end=end, completion_min=completion_min))
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh directory; must not already exist')
    args = parser.parse_args()
    print(json.dumps({'cases': len(generate(args.output))}))


if __name__ == '__main__':
    main()
