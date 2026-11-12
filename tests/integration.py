#!/usr/bin/env python3
"""Protocol-v2 regression tests. Uses only Python's standard library and loopback sockets."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('P2P_BIN_ROOT', ROOT))
PIECE = 524288


def pack(fields):
    fields = [f.encode() if isinstance(f, str) else f for f in fields]
    return struct.pack('!I', len(fields)) + b''.join(struct.pack('!I', len(f)) + f for f in fields)


def unpack(data):
    count, = struct.unpack_from('!I', data)
    offset, fields = 4, []
    for _ in range(count):
        length, = struct.unpack_from('!I', data, offset)
        offset += 4
        fields.append(data[offset:offset + length])
        offset += length
    assert offset == len(data)
    return fields


def exact(s, n):
    data = b''
    while len(data) < n:
        b = s.recv(n - len(data))
        if not b:
            raise ConnectionError('unexpected EOF')
        data += b
    return data


def receive(s):
    length, = struct.unpack('!I', exact(s, 4))
    assert length <= 1048576
    return unpack(exact(s, length))


def transmit(s, fields):
    payload = pack(fields)
    s.sendall(struct.pack('!I', len(payload)) + payload)


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Process:
    def __init__(self, executable, args, cwd):
        self.output = b''
        self.proc = subprocess.Popen([str(executable), *map(str, args)], cwd=cwd,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.expected_crash = False

    def _read(self):
        while True:
            b = os.read(self.proc.stdout.fileno(), 65536)
            if not b:
                return
            self.output += b

    def wait(self, needle, start=0, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle.encode() in self.output[start:]:
                return self.output[start:].decode(errors='replace')
            if self.proc.poll() is not None:
                break
            time.sleep(.01)
        raise AssertionError(f'Missing {needle!r}; exit={self.proc.poll()}\n{self.output[start:].decode(errors="replace")[-6000:]}')

    def send(self, command):
        start = len(self.output)
        self.proc.stdin.write((command + '\n').encode())
        self.proc.stdin.flush()
        return start

    def cmd(self, command, expected='SUCCESS', timeout=8):
        start = self.send(command)
        output = self.wait(expected, start, timeout)
        self.wait('> ', start, timeout)
        return output

    def stop(self, crash=False):
        if self.proc.poll() is None:
            if crash:
                self.expected_crash = True
                self.proc.kill()
            else:
                self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise AssertionError('process did not shut down within 15 seconds')
        self.reader.join(timeout=1)
        if not self.expected_crash:
            assert self.proc.returncode == 0, self.output[-5000:]
        for stream in [self.proc.stdin, self.proc.stdout]:
            stream.close()


class Environment:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p2p-regression-')
        self.path = Path(self.temp.name)
        self.ports = [port(), port()]
        self.info = self.path / 'tracker_info.txt'
        self.info.write_text(''.join(f'127.0.0.1:{p}\n' for p in self.ports))
        self.processes, self.trackers = [], {}
        try:
            self.start_tracker(1)
            self.start_tracker(2)
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def start_tracker(self, identity, partitioned=False):
        cwd = self.path / f'tracker{identity}'
        cwd.mkdir(exist_ok=True)
        info = self.info
        if partitioned:
            ports = list(self.ports)
            ports[2 - identity] = port()
            info = self.path / f'partition-{identity}.txt'
            info.write_text(''.join(f'127.0.0.1:{p}\n' for p in ports))
        proc = Process(BIN / 'tracker/tracker', [info, identity, str(self.info) + '.key'], cwd)
        self.processes.append(proc)
        proc.wait('Tracker listening')
        self.trackers[identity] = proc
        return proc

    def wire(self, identity, fields):
        with socket.create_connection(('127.0.0.1', self.ports[identity - 1]), timeout=10) as s:
            transmit(s, fields)
            return receive(s)

    def rpc(self, command, args=(), token=b'', identity=1, rid=None, error=False):
        rid = rid or uuid.uuid4().hex
        outer = self.wire(identity, ['RPC', rid, token, command, pack(args)])
        assert len(outer) == 4 and outer[0] == b'SIGNED' and outer[1] == rid.encode(), outer
        response = unpack(outer[2])
        if error:
            assert response[0] == b'ERROR', response
        else:
            assert response[0] == b'OK', response
        return response

    def user(self, uid, endpoint=None, identity=1):
        self.rpc('create_user', [uid, 'pw'], identity=identity)
        return self.rpc('login', [uid, 'pw', endpoint or f'127.0.0.1:{port()}'], identity=identity)[2]

    def client(self, name, peerport=None, info=None):
        cwd = self.path / name
        cwd.mkdir(exist_ok=True)
        pport = peerport or port()
        proc = Process(BIN / 'client/client', [f'127.0.0.1:{pport}', info or self.info], cwd)
        proc.peerport, proc.cwd = pport, cwd
        self.processes.append(proc)
        proc.wait('Peer listener started')
        return proc

    def cli_user(self, name):
        c = self.client(name)
        c.cmd(f'create_user {name} pw')
        c.cmd(f'login {name} pw')
        return c

    def join(self, owner, client, uid, gid='grp'):
        client.cmd(f'join_group {gid}')
        owner.cmd(f'accept_request {gid} {uid}')

    def close(self):
        errors = []
        # Stop clients before trackers, enabling orderly logout.
        trackers = set(self.trackers.values())
        for p in [x for x in self.processes if x not in trackers] + list(trackers):
            try:
                p.stop()
                assert b'AddressSanitizer:' not in p.output and b'runtime error:' not in p.output, p.output[-5000:]
            except Exception as e:
                errors.append(e)
        if os.environ.get('P2P_KEEP_TEST_LOGS') or errors:
            out = ROOT / 'tests' / 'last-run-logs'
            out.mkdir(exist_ok=True)
            for i, p in enumerate(self.processes):
                (out / f'{self.path.name}-{i}.log').write_bytes(p.output)
        self.temp.cleanup()
        if errors:
            raise errors[0]


class Peer:
    def __init__(self, data, mode='good'):
        self.data, self.mode = data, mode
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.stopping = threading.Event()
        self.requests = []
        self.connections = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopping.is_set():
            try:
                self.listener.settimeout(.1)
                try:
                    s, _ = self.listener.accept()
                except socket.timeout:
                    continue
                self.connections.append(s)
                if self.mode == 'stall':
                    continue
                with s:
                    request = receive(s)
                    index = int(request[4])
                    self.requests.append(index)
                    data = self.data[index * PIECE:(index + 1) * PIECE]
                    if self.mode == 'corrupt':
                        data = bytes([data[0] ^ 255]) + data[1:]
                    if self.mode == 'disconnect':
                        payload = pack([b'OK', data])
                        s.sendall(struct.pack('!I', len(payload)) + payload[:20])
                    else:
                        transmit(s, [b'OK', data])
            except OSError:
                if not self.stopping.is_set():
                    continue

    def close(self):
        self.stopping.set()
        self.listener.close()
        for s in self.connections:
            s.close()
        self.thread.join(timeout=2)


class TrackerProxy:
    """Fragment valid replies or inject one untrusted reply without possessing the signing key."""
    def __init__(self, target):
        self.target = target
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.stopping = threading.Event()
        self.mode = 'fragment'
        self.handlers = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def handle(self, s):
        try:
            with s:
                s.settimeout(5)
                request = receive(s)
                with socket.create_connection(('127.0.0.1', self.target), timeout=5) as upstream:
                    transmit(upstream, request)
                    response = receive(upstream)
                if self.mode == 'untrusted' and len(request) == 5 and request[3] == b'download_file':
                    response = [b'ERROR ' + b'X' * 8186]
                payload = pack(response)
                framed = struct.pack('!I', len(payload)) + payload
                middle = max(5, len(framed) // 2)
                s.sendall(framed[:middle])
                time.sleep(.05)
                s.sendall(framed[middle:])
        except (OSError, ConnectionError):
            pass

    def run(self):
        while not self.stopping.is_set():
            try:
                self.listener.settimeout(.1)
                try:
                    s, _ = self.listener.accept()
                except socket.timeout:
                    continue
                t = threading.Thread(target=self.handle, args=(s,), daemon=True)
                self.handlers.append(t)
                t.start()
            except OSError:
                break

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)
        for t in self.handlers:
            t.join(timeout=6)


def metadata(data):
    return pack([str(len(data)), hashlib.sha1(data).hexdigest(),
                 pack([hashlib.sha1(data[i:i + PIECE]).hexdigest() for i in range(0, len(data), PIECE)])])


class Integration(unittest.TestCase):
    def setUp(self):
        self.env = Environment()
        self.addCleanup(self.env.close)

    def pair(self):
        a, b = self.env.cli_user('alice'), self.env.cli_user('bob')
        a.cmd('create_group grp')
        self.env.join(a, b, 'bob')
        return a, b

    def source(self, name, data):
        p = self.env.path / name
        p.write_bytes(data)
        return p

    def test_piece_boundaries_renaming_and_persistent_status(self):
        a, b = self.pair()
        for size in [0, 1, PIECE - 1, PIECE, PIECE + 1, 4 * 1024 * 1024]:
            data = os.urandom(size)
            source = self.source(f'file-{size}.bin', data)
            a.cmd(f'upload_file grp {shlex.quote(str(source))}')
            dest = b.cwd / f'renamed-{size}.bin'
            start = b.send(f'download_file grp {source.name} {dest}')
            b.wait('Tracker registered you as seeder', start)
            self.assertEqual(dest.read_bytes(), data)
            b.cmd('show_downloads', '[C] [grp]')
            owner = self.env.rpc('login', ['alice', 'pw', f'127.0.0.1:{port()}'], error=True)
            self.assertIn(b'already logged in', owner[1])
        b.stop()
        restarted = self.env.client('bob', b.peerport)
        restarted.cmd('login bob pw')
        self.assertIn('file-4194304.bin', restarted.cmd('show_downloads', '[C] [grp]'))

    def test_two_real_seeders_and_original_identity_after_rename(self):
        a, b = self.pair()
        c = self.env.cli_user('carol')
        self.env.join(a, c, 'carol')
        data = os.urandom(PIECE * 8 + 31)
        source = self.source('payload.bin', data)
        a.cmd(f'upload_file grp {source}')
        start = b.send(f'download_file grp payload.bin {b.cwd / "different.bin"}')
        b.wait('Tracker registered you as seeder', start)
        start = c.send(f'download_file grp payload.bin {c.cwd / "payload.bin"}')
        out = c.wait('Tracker registered you as seeder', start)
        self.assertIn(f'from 127.0.0.1:{a.peerport}', out)
        self.assertIn(f'from 127.0.0.1:{b.peerport}', out)
        self.assertEqual((c.cwd / 'payload.bin').read_bytes(), data)
        a.cmd('stop_share grp payload.bin')
        c.cmd('stop_share grp payload.bin')
        start = c.send(f'download_file grp payload.bin {c.cwd / "second.bin"}')
        c.wait('Tracker registered you as seeder', start)
        self.assertEqual((c.cwd / 'second.bin').read_bytes(), data)

    def test_cross_tracker_sessions_and_authenticated_failover(self):
        a = self.env.user('alice', identity=1)
        b = self.env.user('bob', identity=2)
        self.env.rpc('create_group', ['grp'], a)
        self.env.rpc('join_group', ['grp'], b, identity=2)
        self.env.rpc('accept_request', ['grp', 'bob'], a)
        self.env.rpc('upload_file', ['grp', 'file.bin', metadata(b'hello')], a)
        response = self.env.rpc('download_file', ['grp', 'file.bin'], b, identity=2)
        self.assertEqual(len(unpack(response[3])), 1)
        self.env.rpc('login', ['alice', 'pw', f'127.0.0.1:{port()}'], identity=2, error=True)
        client = self.env.cli_user('carol')
        self.env.trackers[1].stop(crash=True)
        client.cmd('create_group survived')
        self.env.rpc('create_group', ['still_authenticated'], b, identity=2)

    def test_recovery_preserves_acknowledged_writes_and_full_shutdown(self):
        owner = self.env.user('alice')
        self.env.rpc('create_group', ['original'], owner)
        self.env.trackers[2].stop(crash=True)
        self.env.rpc('create_user', ['while_offline', 'pw'])
        self.env.start_tracker(2)
        session = self.env.rpc('login', ['while_offline', 'pw', f'127.0.0.1:{port()}'], identity=2)[2]
        self.env.rpc('create_group', ['preserved'], session, identity=2)
        self.env.trackers[1].stop()
        self.env.trackers[2].stop()
        self.env.start_tracker(2)
        self.env.start_tracker(1)
        result = self.env.rpc('list_groups', [], session)
        self.assertIn(b'preserved', result)
        self.assertIn(b'original', result)

    def test_idempotent_mutation_retries(self):
        rid = uuid.uuid4().hex
        first = self.env.rpc('create_user', ['alice', 'pw'], rid=rid)
        second = self.env.rpc('create_user', ['alice', 'pw'], rid=rid, identity=2)
        self.assertEqual(first, second)
        self.env.rpc('create_user', ['other', 'pw'], rid=rid, error=True)
        token = self.env.rpc('login', ['alice', 'pw', f'127.0.0.1:{port()}'])[2]
        self.env.rpc('create_group', ['grp'], token)
        self.env.rpc('create_group', ['grp'], token, error=True)

    def test_partitioned_independent_writes_merge_without_loss(self):
        token = self.env.user('alice')
        self.env.rpc('create_group', ['base'], token)
        self.env.trackers[1].stop()
        self.env.trackers[2].stop()
        self.env.start_tracker(1, partitioned=True)
        self.env.start_tracker(2, partitioned=True)
        self.env.rpc('create_user', ['partition_one', 'pw'], identity=1)
        self.env.rpc('create_user', ['partition_two', 'pw'], identity=2)
        self.env.rpc('create_group', ['first'], token, identity=1)
        self.env.rpc('create_group', ['second'], token, identity=2)
        self.env.trackers[1].stop()
        self.env.trackers[2].stop()
        self.env.start_tracker(1)
        self.env.start_tracker(2)
        for identity in [1, 2]:
            response = self.env.rpc('list_groups', [], token, identity=identity)
            self.assertTrue({b'base', b'first', b'second'}.issubset(response))
        for uid in ['partition_one', 'partition_two']:
            self.env.rpc('login', [uid, 'pw', f'127.0.0.1:{port()}'], identity=2)

    def test_concurrent_connected_writes_are_not_lost(self):
        def create(index):
            return self.env.rpc('create_user', [f'user{index}', 'pw'], identity=index % 2 + 1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            self.assertEqual(len(list(executor.map(create, range(16)))), 16)
        self.env.trackers[1].stop(crash=True)
        for index in range(16):
            self.env.rpc('login', [f'user{index}', 'pw', f'127.0.0.1:{port()}'], identity=2)

    def test_partition_conflicts_converge_to_documented_winner(self):
        self.env.trackers[1].stop()
        self.env.trackers[2].stop()
        self.env.start_tracker(1, partitioned=True)
        self.env.start_tracker(2, partitioned=True)
        self.env.rpc('create_user', ['same_user', 'left_password'], identity=1)
        self.env.rpc('create_user', ['same_user', 'right_password'], identity=2)
        self.env.trackers[1].stop()
        self.env.trackers[2].stop()
        self.env.start_tracker(1)
        self.env.start_tracker(2)
        token = self.env.rpc('login', ['same_user', 'left_password', f'127.0.0.1:{port()}'])[2]
        self.env.rpc('logout', [], token)
        self.env.trackers[1].stop(crash=True)
        self.env.rpc('login', ['same_user', 'right_password', f'127.0.0.1:{port()}'], identity=2, error=True)
        self.env.rpc('login', ['same_user', 'left_password', f'127.0.0.1:{port()}'], identity=2)

    def test_command_argument_positions_and_invalid_files(self):
        a, b = self.pair()
        a.cmd('create_group a')
        self.env.join(a, b, 'bob', 'a')
        source = self.source('quoted name: data.bin', b'not a path substring')
        a.cmd(f'upload_file a {shlex.quote(str(source))}')
        start = b.send(f'download_file a {shlex.quote(source.name)} {shlex.quote(str(b.cwd))}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / source.name).read_bytes(), source.read_bytes())
        a.cmd(f'upload_file a {a.cwd}', 'ERROR')
        a.cmd('upload_file a /missing/source.bin', 'ERROR')
        long_source = self.source('x' * 251 + '.bin', b'valid 255-byte basename')
        a.cmd(f'upload_file a {long_source}')
        start = b.send(f'download_file a {long_source.name} {b.cwd}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / long_source.name).read_bytes(), long_source.read_bytes())
        self.assertFalse(list(b.cwd.glob('*.part')))

    def test_group_scope_logout_and_unauthorized_peer_access(self):
        a, b = self.pair()
        a.cmd('create_group other')
        b.cmd('join_group other')
        a.cmd('accept_request other bob')
        source = self.source('same name: file.bin', os.urandom(PIECE + 13))
        a.cmd(f'upload_file grp {shlex.quote(str(source))}')
        a.cmd(f'upload_file other {shlex.quote(str(source))}')
        a.cmd(f'stop_share other {shlex.quote(source.name)}')
        start = b.send(f'download_file grp {shlex.quote(source.name)} {b.cwd / "copy.bin"}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / 'copy.bin').read_bytes(), source.read_bytes())
        with socket.create_connection(('127.0.0.1', a.peerport), timeout=4) as s:
            transmit(s, ['GET', 'forged-ticket', 'grp', hashlib.sha1(source.read_bytes()).hexdigest(), '0'])
            self.assertEqual(receive(s)[0], b'ERROR')
        # Obtain a valid ticket before logout, then reuse it against the old seeder.
        raw = self.env.user('carol')
        self.env.rpc('join_group', ['grp'], raw)
        a.cmd('accept_request grp carol')
        response = self.env.rpc('download_file', ['grp', source.name], raw)
        a.cmd('logout')
        with socket.create_connection(('127.0.0.1', a.peerport), timeout=4) as s:
            transmit(s, ['GET', response[4], 'grp', hashlib.sha1(source.read_bytes()).hexdigest(), '0'])
            self.assertEqual(receive(s)[0], b'ERROR')
        b.cmd('leave_group missing', 'ERROR')
        b.cmd('leave_group grp')
        b.cmd('list_files grp', 'ERROR')

    def test_owner_leave_transfers_or_deletes_group(self):
        a, b = self.pair()
        a.cmd('leave_group grp')
        b.cmd('list_requests grp', 'REQUESTS')
        b.cmd('leave_group grp')
        self.assertNotIn('\ngrp\n', b.cmd('list_groups', 'GROUPS'))

    def test_conflicting_content_and_failed_share_are_isolated(self):
        a, b = self.pair()
        folder = self.env.path / 'other-directory'
        folder.mkdir()
        first = self.source('same.bin', b'first')
        second = folder / 'same.bin'
        second.write_bytes(b'second')
        a.cmd(f'upload_file grp {first}')
        b.cmd(f'upload_file grp {second}', 'ERROR')
        b.cmd('stop_share grp same.bin', 'ERROR')
        start = b.send(f'download_file grp same.bin {b.cwd / "copy.bin"}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / 'copy.bin').read_bytes(), b'first')

    def test_existing_destination_is_preserved(self):
        a, b = self.pair()
        source = self.source('file.bin', b'new data')
        a.cmd(f'upload_file grp {source}')
        dest = b.cwd / 'file.bin'
        dest.write_bytes(b'valuable old data')
        b.cmd(f'download_file grp file.bin {dest}', 'ERROR')
        self.assertEqual(dest.read_bytes(), b'valuable old data')

    def test_fragmented_and_coalesced_protocol_and_malformed_requests(self):
        payload = pack(['HELLO'])
        framed = struct.pack('!I', len(payload)) + payload
        with socket.create_connection(('127.0.0.1', self.env.ports[0]), timeout=4) as s:
            for chunk in [framed[:2], framed[2:7], framed[7:]]:
                s.sendall(chunk)
                time.sleep(.03)
            self.assertEqual(receive(s)[:2], [b'OK', b'P2P/2'])
        # Multiple complete frames in one TCP write remain separate requests.
        with socket.create_connection(('127.0.0.1', self.env.ports[0]), timeout=4) as s:
            s.sendall(framed + framed)
            self.assertEqual(receive(s)[0], b'OK')
            self.assertEqual(receive(s)[0], b'OK')
        for bad in [struct.pack('!I', 0xffffffff), struct.pack('!I', 8) + b'\xff' * 8,
                    b'SYNC\nUSER injected pw\nEND\n']:
            with socket.create_connection(('127.0.0.1', self.env.ports[0]), timeout=4) as s:
                s.sendall(bad)
                try:
                    self.assertEqual(receive(s)[0], b'ERROR')
                except ConnectionError:
                    pass
        self.env.rpc('login', ['alice', 'pw', '127.0.0.1:notaport'], error=True)
        self.env.rpc('login', ['injected', 'pw', '127.0.0.1:1234'], error=True)
        owner = self.env.user('alice')
        self.env.rpc('create_group', ['grp'], owner)
        invalid = pack(['524289', hashlib.sha1(b'X').hexdigest(), pack([hashlib.sha1(b'X').hexdigest()])])
        self.env.rpc('upload_file', ['grp', 'bad.bin', invalid], owner, error=True)
        self.env.rpc('create_user', ['still_alive', 'pw'])
        response = self.env.wire(1, ['REPLICA', str(int(time.time())), uuid.uuid4().hex,
                                     pack(['SYNC', pack(['0', '0']), pack([]), pack([])]), '0' * 64])
        self.assertEqual(response[0], b'ERROR')

    def test_fragmented_tracker_responses_and_forged_response_failover(self):
        a = self.env.cli_user('alice')
        a.cmd('create_group grp')
        proxy = TrackerProxy(self.env.ports[0])
        self.addCleanup(proxy.close)
        info = self.env.path / 'proxy-info.txt'
        info.write_text(f'127.0.0.1:{proxy.port}\n127.0.0.1:{self.env.ports[1]}\n')
        b = self.env.client('bob', info=info)
        b.cmd('create_user bob pw')
        b.cmd('login bob pw')
        self.env.join(a, b, 'bob')
        source = self.source('fragmented.bin', os.urandom(PIECE + 17))
        a.cmd(f'upload_file grp {source}')
        start = b.send(f'download_file grp fragmented.bin {b.cwd / "first.bin"}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / 'first.bin').read_bytes(), source.read_bytes())
        proxy.mode = 'untrusted'
        start = b.send(f'download_file grp fragmented.bin {b.cwd / "second.bin"}')
        b.wait('Tracker registered you as seeder', start)
        self.assertEqual((b.cwd / 'second.bin').read_bytes(), source.read_bytes())

    def test_leaving_group_revokes_previously_issued_ticket(self):
        a = self.env.cli_user('alice')
        a.cmd('create_group grp')
        requester = self.env.user('bob')
        self.env.rpc('join_group', ['grp'], requester)
        a.cmd('accept_request grp bob')
        source = self.source('file.bin', b'private group data')
        a.cmd(f'upload_file grp {source}')
        response = self.env.rpc('download_file', ['grp', 'file.bin'], requester)
        self.env.rpc('leave_group', ['grp'], requester)
        with socket.create_connection(('127.0.0.1', a.peerport), timeout=4) as s:
            transmit(s, ['GET', response[4], 'grp', hashlib.sha1(source.read_bytes()).hexdigest(), '0'])
            self.assertEqual(receive(s)[0], b'ERROR')

    def with_peers(self, modes):
        data = os.urandom(PIECE * 2 + 7)
        peers = [Peer(data, mode) for mode in modes]
        for peer in peers:
            self.addCleanup(peer.close)
        owners = [self.env.user('owner' + str(i), f'127.0.0.1:{peer.port}') for i, peer in enumerate(peers)]
        self.env.rpc('create_group', ['grp'], owners[0])
        for i, owner in enumerate(owners[1:], 1):
            self.env.rpc('join_group', ['grp'], owner)
            self.env.rpc('accept_request', ['grp', 'owner' + str(i)], owners[0])
        for owner in owners:
            self.env.rpc('upload_file', ['grp', 'file.bin', metadata(data)], owner)
        b = self.env.cli_user('bob')
        b.cmd('join_group grp')
        self.env.rpc('accept_request', ['grp', 'bob'], owners[0])
        return b, data, peers

    def test_corrupted_and_disconnected_peers_retry_elsewhere(self):
        b, data, peers = self.with_peers(['corrupt', 'disconnect', 'good'])
        dest = b.cwd / 'file.bin'
        start = b.send(f'download_file grp file.bin {dest}')
        b.wait('Tracker registered you as seeder', start, timeout=15)
        self.assertEqual(dest.read_bytes(), data)
        self.assertTrue(peers[0].requests and peers[1].requests and peers[2].requests)

    def test_stalled_peer_deadline_and_simultaneous_downloads(self):
        b, data, peers = self.with_peers(['stall', 'good'])
        owner = self.env.rpc('login', ['owner1', 'pw', '127.0.0.1:1234'], error=True)
        self.assertIn(b'already logged in', owner[1])
        # Same content, independent network filename, to exercise concurrent jobs.
        token = self.env.user('extra', f'127.0.0.1:{peers[1].port}')
        self.env.rpc('join_group', ['grp'], token)
        # owner0 is raw; its bearer token is deliberately not exposed by the fixture.
        # Use the existing downloader to create its own group for the second job.
        b.cmd('create_group second')
        self.env.rpc('join_group', ['second'], token)
        b.cmd('accept_request second extra')
        self.env.rpc('upload_file', ['second', 'other.bin', metadata(data)], token)
        start = b.send(f'download_file grp file.bin {b.cwd / "first.bin"}')
        b.wait('SUCCESS download started', start)
        out = b.cmd('show_downloads', '[D] [grp]')
        self.assertIn('file.bin', out)
        b.cmd(f'download_file second other.bin {b.cwd / "second.bin"}', 'SUCCESS download started')
        b.cmd('list_groups', 'GROUPS')
        b.wait('SUCCESS file downloaded to ' + str(b.cwd / 'first.bin'), start, 15)
        b.wait('SUCCESS file downloaded to ' + str(b.cwd / 'second.bin'), start, 15)
        self.assertEqual((b.cwd / 'first.bin').read_bytes(), data)
        self.assertEqual((b.cwd / 'second.bin').read_bytes(), data)

    def test_tracker_failure_during_download_preserves_jobs_and_registration(self):
        b, data, _ = self.with_peers(['stall', 'good'])
        dest = b.cwd / 'failover.bin'
        start = b.send(f'download_file grp file.bin {dest}')
        b.wait('SUCCESS download started', start)
        b.cmd('show_downloads', '[D] [grp]')
        self.env.trackers[1].stop(crash=True)
        b.cmd('create_group still_authenticated')
        b.wait('Tracker registered you as seeder', start, 15)
        self.assertEqual(dest.read_bytes(), data)
        b.cmd('stop_share grp file.bin')

    def test_failed_download_reports_failure_without_hanging_or_partial_output(self):
        owner = self.env.user('alice')
        self.env.rpc('create_group', ['grp'], owner)
        self.env.rpc('upload_file', ['grp', 'missing.bin', metadata(b'data')], owner)
        b = self.env.cli_user('bob')
        b.cmd('join_group grp')
        self.env.rpc('accept_request', ['grp', 'bob'], owner)
        dest = b.cwd / 'copy.bin'
        start = b.send(f'download_file grp missing.bin {dest}')
        b.wait('ERROR download', start, 12)
        b.cmd('list_groups', 'GROUPS')
        self.assertFalse(dest.exists())
        self.assertFalse(list(b.cwd.glob('*.part')))
        b.cmd('show_downloads', '[F] [grp]')

    def test_full_file_hash_mismatch_does_not_publish(self):
        b, data, _ = self.with_peers(['good'])
        # Different filename and valid piece hashes, with an inconsistent complete-file hash.
        token = self.env.user('extra', f'127.0.0.1:{port()}')
        b.cmd('create_group other')
        self.env.rpc('join_group', ['other'], token)
        b.cmd('accept_request other extra')
        peer = Peer(data)
        self.addCleanup(peer.close)
        self.env.rpc('logout', [], token)
        token = self.env.rpc('login', ['extra', 'pw', f'127.0.0.1:{peer.port}'])[2]
        bad = unpack(metadata(data))
        bad[1] = b'0' * 40
        self.env.rpc('upload_file', ['other', 'bad.bin', pack(bad)], token)
        dest = b.cwd / 'bad.bin'
        start = b.send(f'download_file other bad.bin {dest}')
        b.wait('final file hash mismatch', start)
        b.cmd('list_groups', 'GROUPS')
        self.assertFalse(dest.exists())
        self.assertFalse(list(b.cwd.glob('*.part')))

    def test_incomplete_journal_tail_is_recovered(self):
        token = self.env.user('alice')
        self.env.rpc('create_group', ['retained'], token)
        self.env.trackers[1].stop(crash=True)
        path = self.env.path / 'tracker1/tracker_state_1.log'
        with path.open('ab') as f:
            f.write(struct.pack('!I', 100) + b'partial')
        tracker = self.env.start_tracker(1)
        self.assertIn(b'Recovered incomplete', tracker.output)
        self.assertIn(b'retained', self.env.rpc('list_groups', [], token))

    @unittest.skipUnless(os.environ.get('P2P_LARGE_TEST'), 'set P2P_LARGE_TEST=1 for 1 GiB transfer')
    def test_one_gib_transfer(self):
        a, b = self.pair()
        source = self.env.path / 'one-gib.bin'
        with source.open('wb') as f:
            f.truncate(1024 ** 3)
        upload_started = time.monotonic()
        a.cmd(f'upload_file grp {source}', timeout=60)
        upload_seconds = time.monotonic() - upload_started
        dest = b.cwd / source.name
        samples, sampling = [], threading.Event()
        def sample_rss():
            while not sampling.is_set():
                try:
                    value = subprocess.check_output(['ps', '-o', 'rss=', '-p', str(b.proc.pid)], text=True)
                    samples.append(int(value.strip()))
                except (OSError, ValueError, subprocess.CalledProcessError):
                    pass
                sampling.wait(.1)
        sampler = threading.Thread(target=sample_rss, daemon=True)
        sampler.start()
        download_started = time.monotonic()
        try:
            start = b.send(f'download_file grp {source.name} {dest}')
            b.wait('Tracker registered you as seeder', start, timeout=120)
        finally:
            sampling.set()
            sampler.join()
        download_seconds = time.monotonic() - download_started
        self.assertEqual(dest.stat().st_size, 1024 ** 3)
        def sha(path):
            h = hashlib.sha1()
            with path.open('rb') as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            return h.hexdigest()
        source_hash, destination_hash = sha(source), sha(dest)
        self.assertEqual(source_hash, destination_hash)
        measurement = {'bytes': dest.stat().st_size, 'upload_hash_and_register_seconds': round(upload_seconds, 3),
                       'download_verify_and_register_seconds': round(download_seconds, 3),
                       'downloader_peak_sampled_rss_kib': max(samples) if samples else None,
                       'source_sha1': source_hash, 'destination_sha1': destination_hash,
                       'environment': 'single machine, loopback, sparse zero-filled source; RSS sampled every 100 ms'}
        print(json.dumps(measurement), flush=True)
        if os.environ.get('P2P_BENCHMARK_OUTPUT'):
            Path(os.environ['P2P_BENCHMARK_OUTPUT']).write_text(json.dumps(measurement, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
