"""Recover only a verified prefix of a run-owned compressed binary upload.

Management reconnection never starts/restarts a business process. Original ELF
and compressed hashes, attempt errors and offsets are retained by the caller.
No credentials are accepted, returned or logged by this module.
"""
from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
import time
import threading

import remote

MAX_BINARY = 16*1024*1024
CHUNK = 32*1024
BATCH_CHUNKS = 4
MAX_CONNECTIONS = 3
TRANSFER_SECONDS = 180

def upload_binary(run, path, progress=None):
    data = Path(path).read_bytes()
    if not data.startswith(b'\x7fELF') or not 4 <= len(data) <= MAX_BINARY:
        raise remote.LabError('bounded staging requires a bounded Linux ELF')
    packed = gzip.compress(data, compresslevel=6, mtime=0)
    if len(packed) > MAX_BINARY:
        raise remote.LabError('bounded compressed staging size exceeded')
    digest = hashlib.sha256(data).hexdigest()
    packed_digest = hashlib.sha256(packed).hexdigest()
    report = {'method': 'gzip-verified-prefix-bounded-batch-sftp-v2.1', 'bytes':len(data),
              'sha256':digest, 'compressed_bytes':len(packed), 'compressed_sha256':packed_digest,
              'chunk_bytes':CHUNK, 'max_outstanding_chunks':BATCH_CHUNKS, 'max_connections':MAX_CONNECTIONS,
              'transfer_deadline_seconds':TRANSFER_SECONDS, 'attempts':[], 'pass':False}
    started = time.monotonic()
    deadline = started+TRANSFER_SECONDS
    name = 'binary.gz.part'
    def emit():
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        if progress: progress(report)
    prefix_script = run._check()+r'''
import hashlib,stat
f=p/'binary.gz.part'
if not f.exists():
    fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
st=f.lstat()
if not stat.S_ISREG(st.st_mode) or st.st_size>%r or str(f.resolve())!=str(f):raise RuntimeError('invalid owned upload prefix')
print(json.dumps({'bytes':st.st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}))
''' % len(packed)
    for attempt in range(MAX_CONNECTIONS):
        item = {'attempt':attempt+1, 'success':False}
        report['attempts'].append(item)
        emit()
        sftp = None
        try:
            if time.monotonic() >= deadline:
                raise remote.LabError('fixed upload deadline exceeded')
            if attempt:
                run.remote.close()
                run.remote.connect()
                item['management_reconnected'] = True
            prefix = run.remote.python(prefix_script, timeout=min(30,max(1,deadline-time.monotonic())))
            offset = prefix['bytes']
            if prefix['sha256'] != hashlib.sha256(packed[:offset]).hexdigest():
                raise remote.LabError('partial upload prefix mismatch')
            item['verified_start_offset'] = offset
            # A timer also closes the owned management transport if library
            # subsystem initialization fails to respect the socket timeout.
            upload_timer=threading.Timer(max(0,deadline-time.monotonic()),run.remote.close)
            upload_timer.daemon=True
            upload_timer.start()
            try:
                sftp = run.remote.client.open_sftp()
                sftp.get_channel().settimeout(min(15,max(1,deadline-time.monotonic())))
                with sftp.open(run.directory+'/'+name, 'r+') as stream:
                    stream.seek(offset)
                    for batch in range(offset,len(packed),BATCH_CHUNKS*CHUNK):
                        end=min(batch+BATCH_CHUNKS*CHUNK,len(packed))
                        positions=list(range(batch,end,CHUNK))
                        for position in positions:
                            if time.monotonic() >= deadline:
                                raise remote.LabError('fixed upload deadline exceeded')
                            sftp.get_channel().settimeout(min(15,max(1,deadline-time.monotonic())))
                            # Paramiko's last non-pipelined _write drains every
                            # prior status before returning. At most four write
                            # requests can be outstanding, including this one.
                            stream.set_pipelined(position != positions[-1])
                            stream.write(packed[position:min(position+CHUNK,end)])
                        item['acknowledged_offset'] = end
                sftp.close();sftp=None
            finally:
                upload_timer.cancel()
            if time.monotonic() >= deadline:
                raise remote.LabError('fixed upload deadline exceeded before commit')
            # Commit to a distinct executable only after full compressed and
            # uncompressed proofs. Decompression has a strict output budget.
            commit_script = run._check()+r'''
import gzip,hashlib,stat
archive=p/'binary.gz.part';output=p/'bfp'
st=archive.lstat()
if not stat.S_ISREG(st.st_mode) or st.st_size!=%r or hashlib.sha256(archive.read_bytes()).hexdigest()!=%r:raise RuntimeError('compressed upload proof mismatch')
if output.exists() or output.is_symlink():raise RuntimeError('owned executable already exists')
length=0;digest=hashlib.sha256();prefix=b''
fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)
try:
    with os.fdopen(fd,'wb') as target,gzip.open(archive,'rb') as source:
        while True:
            block=source.read(32768)
            if not block:break
            length+=len(block)
            if length>%r:raise RuntimeError('ELF decompression budget exceeded')
            if not prefix:prefix=block[:4]
            digest.update(block);target.write(block)
    if length!=%r or prefix!=b'\x7fELF' or digest.hexdigest()!=%r:raise RuntimeError('ELF upload proof mismatch')
except Exception:
    output.unlink(missing_ok=True)
    raise
print(json.dumps({'bytes':length,'sha256':digest.hexdigest(),'compressed_sha256':%r,'mode':oct(output.stat().st_mode&0o777)}))
''' % (len(packed),packed_digest,len(data),len(data),digest,packed_digest)
            committed = run.remote.python(commit_script, timeout=min(30,max(1,deadline-time.monotonic())))
            if time.monotonic() >= deadline:
                raise remote.LabError('fixed upload deadline exceeded during commit')
            if committed['sha256'] != digest or committed['bytes'] != len(data):
                raise remote.LabError('remote ELF proof mismatch')
            item['success']=True
            report['pass']=True
            report['committed']=committed
            emit()
            return report
        except Exception as error:
            item['error_type']=type(error).__name__
            item['error']=remote.SANITIZER.text(str(error))[:1024]
            emit()
            # Owner/path/hash errors cannot be repaired by reconnecting.
            if isinstance(error,remote.LabError) or time.monotonic() >= deadline:
                raise
        finally:
            if sftp:
                try:sftp.close()
                except Exception:pass
    raise remote.LabError('bounded management upload attempts exhausted')
