"""Private rehearsal query. stdin is JSON, never shell/argv interpolation.
Freeze processes holding the database open while copying DB + WAL; never copy SHM.
Any snapshot, SQL or consistency error exits nonzero, never eventFound:false.
"""
import contextlib
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


@contextlib.contextmanager
def snapshot(source):
    source = Path(source).resolve(strict=True)
    stopped = []
    try:
        # Root inside the disposable distro can inspect all writers. Hold them
        # stopped across the whole copy, not merely two independent file reads.
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            try:
                if os.geteuid() != 0 and proc.stat().st_uid != os.geteuid():
                    continue
                command = (proc / 'cmdline').read_bytes().split(b'\x00')
                if b'synapse.app.homeserver' not in command:
                    continue
                holds_db = any(Path(os.readlink(fd)) == source for fd in (proc / 'fd').iterdir())
            except (FileNotFoundError, ProcessLookupError):
                continue
            if not holds_db:
                continue
            state = (proc / 'status').read_text().split('State:')[1].splitlines()[0].strip()[0]
            if state not in ('T', 't'):
                os.kill(int(proc.name), signal.SIGSTOP)
                stopped.append(int(proc.name))
            for _ in range(100):
                if (proc / 'status').read_text().split('State:')[1].splitlines()[0].strip()[0] in ('T', 't'):
                    break
                time.sleep(0.01)
            else:
                raise RuntimeError('database writer did not stop')
        with tempfile.TemporaryDirectory(prefix='synapse-ro-') as tmp:
            target = Path(tmp) / 'copy.db'
            signatures = {}
            for suffix in ('', '-wal', '-journal'):
                path = Path(str(source) + suffix)
                if path.exists():
                    signatures[suffix] = hashlib.sha256(path.read_bytes()).digest()
                    shutil.copyfile(path, str(target) + suffix)
            for suffix, expected in signatures.items():
                if hashlib.sha256(Path(str(source) + suffix).read_bytes()).digest() != expected:
                    raise RuntimeError('database changed during snapshot')
                if hashlib.sha256(Path(str(target) + suffix).read_bytes()).digest() != expected:
                    raise RuntimeError('database snapshot differs')
            # Resume before querying the independent private copy.
            for pid in stopped:
                os.kill(pid, signal.SIGCONT)
            stopped.clear()
            yield target
    finally:
        for pid in stopped:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass


def query(args):
    db, room_id, event_id, user_id, canary = args
    if not all(isinstance(v, str) and v for v in args):
        raise ValueError('nonempty string parameters required')
    with snapshot(db) as copied:
        con = sqlite3.connect(copied)
        try:
            if con.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise RuntimeError('inconsistent database snapshot')
            # A missing JSON row is corruption, not normal event absence.
            if con.execute('select 1 from events e left join event_json j using(event_id) where j.event_id is null or e.room_id != j.room_id limit 1').fetchone():
                raise RuntimeError('inconsistent event tables')
            if con.execute('select 1 from current_state_events c left join event_json j using(event_id) where j.event_id is null or c.room_id != j.room_id limit 1').fetchone():
                raise RuntimeError('inconsistent current state')
            row = con.execute('select e.type, j.json, e.event_id, e.room_id, j.event_id, j.room_id from events e join event_json j using(event_id) where e.event_id=? and e.room_id=?', (event_id, room_id)).fetchone()
            types = dict(con.execute('select type, count(*) from events where room_id=? group by type', (room_id,)))
            out = {'eventFound': row is not None, 'roomEventTypesSeen': types,
                   'parameterDigests': [digest(v) for v in (room_id, event_id, user_id)],
                   'identifiersMatch': False, 'databaseConsistent': True}
            if row:
                ev = json.loads(row[1])
                content = ev.get('content', {})
                out.update(eventType=row[0], hasBody='body' in content,
                           contentAlgorithm=content.get('algorithm'), sender=ev.get('sender'),
                           identifiersMatch=(row[2] == row[4] == event_id and row[3] == row[5] == room_id
                                             and ev.get('event_id', event_id) == event_id
                                             and ev.get('room_id', room_id) == room_id
                                             and ev.get('type', row[0]) == row[0]))
            enc = con.execute("select j.json from current_state_events c join event_json j using(event_id) where c.room_id=? and c.type='m.room.encryption' and c.state_key=''", (room_id,)).fetchone()
            out['roomEncryption'] = json.loads(enc[0]).get('content', {}).get('algorithm') if enc else None
            out['devices'] = sorted(r[0] for r in con.execute('select device_id from devices where user_id=? and not hidden', (user_id,)))
            needle = canary.encode('utf-8')
            out['canaryPlaintextInDatabase'] = any(needle in p.read_bytes() for p in (copied, Path(str(copied) + '-wal'), Path(str(copied) + '-journal')) if p.exists())
            return out
        finally:
            con.close()


if __name__ == '__main__':
    try:
        print(json.dumps(query(json.load(sys.stdin)), sort_keys=True))
    except Exception as error:
        # Do not print SQL, identifiers, message content or credential-bearing paths.
        print(json.dumps({'queryError': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
