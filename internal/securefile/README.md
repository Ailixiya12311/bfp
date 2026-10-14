# Credential file boundary

`MakePrivateDir(path)` refuses an existing path. On Unix it creates 0700; on
Windows the directory is created with a protected DACL and one inheritable
FullControl ACE for the current process user SID. No key data exists before
the ACL is applied. `WriteExclusive` requires an already private immediate
parent and creates, verifies, writes and synchronizes a new owner-only file.
It never overwrites an existing file. An incomplete file after an I/O error
remains private; cleanup belongs to the caller.

`Read(path, max)` checks every currently existing path component for links and
opens the final file without following a symlink/reparse point. It verifies the
opened regular file before reading and never reads more than max+1 bytes. A
larger file is rejected. max must be 1..64 MiB; callers should normally use
64 KiB for configuration. This package does not parse JSON, reject trailing
JSON values, or verify that a byte slice contains the expected key structure.

On Unix, file ownership must equal the current effective UID and group/other
mode bits must all be zero. On Windows, ownership must equal the current
process user. NULL/missing DACLs and unsupported conditional/object ACEs are
rejected; every effective nonzero ordinary allow ACE must name that user,
SYSTEM or BUILTIN Administrators. Inherit-only ACEs do not grant file access
and are ignored. The opened read handle does not share writes or deletion.
Generated files and directories have only the current user's allow ACE;
accepted imported files may also grant SYSTEM/Administrators access.

Windows 0600 alone does not establish this ACL; native security attributes do.
No shell commands, installer or additional dependency are required. Normal
parent directory ACLs are accepted when reading a protected file. The package
does not prove every parent is non-writable by an attacker and the ancestor
walk is not atomic against concurrent replacement: deployment paths must still
be trusted. Administrators/root and a compromised current account are outside
the local file protection boundary. The package never logs contents.

Native Windows tests validate creation inheritance protection, owner-only ACL,
Everyone-readable rejection, NULL DACL rejection, trusted SYSTEM/Admin grants,
bounded reads, exclusive create and private files in ordinary directories.
Symlink tests may skip on accounts lacking Windows symlink privileges.
Unix-specific tests compile under Linux and check group/other permission
rejection; executing them requires a Unix host.
