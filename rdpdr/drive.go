// Copyright 2026 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rdpdr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// IRP major and minor function codes (MS-RDPEFS 2.2.1.4).
const (
	irpCreate                 = 0x00
	irpClose                  = 0x02
	irpRead                   = 0x03
	irpWrite                  = 0x04
	irpQueryInformation       = 0x05
	irpSetInformation         = 0x06
	irpQueryVolumeInformation = 0x0A
	irpDirectoryControl       = 0x0C
	irpDeviceControl          = 0x0E
	irpLockControl            = 0x11

	irpMinorQueryDirectory = 0x01
)

// NTSTATUS codes.
const (
	statusSuccess              = 0x00000000
	statusNoMoreFiles          = 0x80000006
	statusUnsuccessful         = 0xC0000001
	statusInvalidHandle        = 0xC0000008
	statusNoSuchFile           = 0xC000000F
	statusInvalidDeviceRequest = 0xC0000010
	statusAccessDenied         = 0xC0000022
	statusObjectNameInvalid    = 0xC0000033
	statusObjectNameNotFound   = 0xC0000034
	statusObjectNameCollision  = 0xC0000035
	statusObjectPathNotFound   = 0xC000003A
	statusFileIsADirectory     = 0xC00000BA
	statusNotSupported         = 0xC00000BB
	statusDirectoryNotEmpty    = 0xC0000101
	statusNotADirectory        = 0xC0000103
)

// CreateDisposition values.
const (
	fileSupersede   = 0
	fileOpen        = 1
	fileCreate      = 2
	fileOpenIf      = 3
	fileOverwrite   = 4
	fileOverwriteIf = 5
)

// Create response Information values.
const (
	infoSuperseded  = 0
	infoOpened      = 1
	infoCreated     = 2
	infoOverwritten = 3
)

// CreateOptions flags.
const (
	optDirectoryFile    = 0x00000001
	optNonDirectoryFile = 0x00000040
	optDeleteOnClose    = 0x00001000
)

// Access mask bits that imply modifying the file.
const accessWrite = 0x00000002 | 0x00000004 | 0x40000000 | 0x10000000 // write data, append, GENERIC_WRITE, GENERIC_ALL

// File attributes.
const (
	attrReadOnly  = 0x00000001
	attrDirectory = 0x00000010
	attrArchive   = 0x00000020
)

// File and volume information classes (MS-FSCC 2.4, 2.5).
const (
	fileDirectoryInformation     = 1
	fileFullDirectoryInformation = 2
	fileBothDirectoryInformation = 3
	fileBasicInformation         = 4
	fileStandardInformation      = 5
	fileRenameInformation        = 10
	fileNamesInformation         = 12
	fileDispositionInformation   = 13
	fileAllocationInformation    = 19
	fileEndOfFileInformation     = 20
	fileAttributeTagInformation  = 35

	fileFsVolumeInformation    = 1
	fileFsSizeInformation      = 3
	fileFsDeviceInformation    = 4
	fileFsAttributeInformation = 5
	fileFsFullSizeInformation  = 7
)

// maxReadLength bounds a single read request.
const maxReadLength = 8 << 20

// Audit operations reported through Drive.OnEvent.
const (
	OpCreate = "create"
	OpMkdir  = "mkdir"
	OpRead   = "read"
	OpWrite  = "write"
	OpDelete = "delete"
	OpRename = "rename"
)

// Event is one auditable operation the remote session performed on a drive.
// Paths are drive-relative with forward slashes, e.g. "/reports/a.txt". Read
// and write events are reported once per file handle, on close, with the total
// byte count.
type Event struct {
	Op      string
	Path    string
	NewPath string
	Bytes   int64
}

// Drive exposes a local directory to the remote session. All paths the server
// sends are confined to the root directory.
type Drive struct {
	Name string
	// ReadOnly forbids the remote session from changing anything in the
	// directory (no file leaves the remote host).
	ReadOnly bool
	// WriteOnly forbids the remote session from reading the contents of files
	// it did not write itself (no file enters the remote host); listing still
	// works.
	WriteOnly bool
	// OnEvent, if set, receives every auditable operation.
	OnEvent func(Event)

	root   string
	files  map[uint32]*openFile
	nextID uint32
	// written holds the paths whose whole content came from the remote session
	// (created or truncated by it), which stay readable under WriteOnly.
	written map[string]bool
}

type openFile struct {
	path     string
	full     string
	isDir    bool
	f        *os.File
	writable bool

	deletePending bool
	entries       []dirEntry
	next          int

	read    int64
	written int64
}

type dirEntry struct {
	name string
	info fs.FileInfo
}

// NewDrive creates a drive named name backed by the directory root.
func NewDrive(name, root string) (*Drive, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("rdpdr: %s is not a directory", root)
	}
	return &Drive{Name: name, root: real, files: map[uint32]*openFile{}, nextID: 1, written: map[string]bool{}}, nil
}

// Close releases every file handle the remote session left open.
func (d *Drive) Close() {
	for id, of := range d.files {
		if of.f != nil {
			_ = of.f.Close()
		}
		delete(d.files, id)
	}
}

// Handle processes one Device I/O Request and returns the Device I/O Response.
func (d *Drive) Handle(req *IORequest) []byte {
	switch req.MajorFunction {
	case irpCreate:
		return d.create(req)
	case irpClose:
		return d.close(req)
	case irpRead:
		return d.read(req)
	case irpWrite:
		return d.write(req)
	case irpQueryInformation:
		return d.queryInformation(req)
	case irpSetInformation:
		return d.setInformation(req)
	case irpQueryVolumeInformation:
		return d.queryVolumeInformation(req)
	case irpDirectoryControl:
		return d.directoryControl(req)
	case irpDeviceControl, irpLockControl:
		return buildCompletion(req, statusSuccess, u32Bytes(0))
	default:
		return buildCompletion(req, statusNotSupported, nil)
	}
}

func (d *Drive) emit(ev Event) {
	if d.OnEvent != nil {
		d.OnEvent(ev)
	}
}

// cleanPath converts a redirector path ("\dir\file") to a drive path
// ("/dir/file"). Cleaning against "/" removes every ".." component.
func cleanPath(p string) string {
	return path.Clean("/" + strings.ReplaceAll(p, `\`, "/"))
}

func validName(p string) bool {
	return !strings.ContainsAny(p, ":*?\"<>|")
}

var errEscape = errors.New("rdpdr: path escapes the drive root")

// resolve maps a drive path to a host path, refusing symlinks that lead out of
// the root.
func (d *Drive) resolve(p string) (string, error) {
	full := filepath.Join(d.root, filepath.FromSlash(p))
	for dir := full; ; {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			if !within(d.root, real) {
				return "", errEscape
			}
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return full, nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func ntStatus(err error, full string) uint32 {
	switch {
	case err == nil:
		return statusSuccess
	case errors.Is(err, errEscape), errors.Is(err, fs.ErrPermission):
		return statusAccessDenied
	case errors.Is(err, fs.ErrExist):
		return statusObjectNameCollision
	case errors.Is(err, fs.ErrNotExist):
		if st, perr := os.Stat(filepath.Dir(full)); perr != nil || !st.IsDir() {
			return statusObjectPathNotFound
		}
		return statusObjectNameNotFound
	default:
		return statusUnsuccessful
	}
}

func (d *Drive) create(req *IORequest) []byte {
	r := newReader(req.Body)
	desired := r.u32()
	r.skip(8) // AllocationSize
	r.skip(4) // FileAttributes
	r.skip(4) // SharedAccess
	disposition := r.u32()
	options := r.u32()
	p := cleanPath(decodeUTF16(r.bytes(int(r.u32()))))

	fail := func(status uint32) []byte {
		return buildCompletion(req, status, createTail(0, 0))
	}
	if !validName(p) {
		return fail(statusObjectNameInvalid)
	}
	full, err := d.resolve(p)
	if err != nil {
		return fail(statusAccessDenied)
	}
	if d.ReadOnly && options&optDeleteOnClose != 0 {
		return fail(statusAccessDenied)
	}

	of := &openFile{path: p, full: full, deletePending: options&optDeleteOnClose != 0}
	info := uint8(infoOpened)
	st, statErr := os.Stat(full)
	exists := statErr == nil

	switch {
	case exists && st.IsDir():
		if disposition == fileCreate {
			return fail(statusObjectNameCollision)
		}
		if options&optNonDirectoryFile != 0 {
			return fail(statusFileIsADirectory)
		}
		of.isDir = true

	case exists && options&optDirectoryFile != 0:
		return fail(statusNotADirectory)

	case !exists && options&optDirectoryFile != 0:
		if disposition != fileCreate && disposition != fileOpenIf {
			return fail(ntStatus(statErr, full))
		}
		if d.ReadOnly {
			return fail(statusAccessDenied)
		}
		if err := os.Mkdir(full, 0o755); err != nil {
			return fail(ntStatus(err, full))
		}
		of.isDir = true
		info = infoCreated
		d.emit(Event{Op: OpMkdir, Path: p})

	default:
		if !exists && (disposition == fileOpen || disposition == fileOverwrite) {
			return fail(ntStatus(statErr, full))
		}
		if exists && disposition == fileCreate {
			return fail(statusObjectNameCollision)
		}
		truncate := exists && (disposition == fileSupersede || disposition == fileOverwrite || disposition == fileOverwriteIf)
		writable := desired&accessWrite != 0 || !exists || truncate
		if d.ReadOnly && writable {
			return fail(statusAccessDenied)
		}
		flag := os.O_RDONLY
		if writable {
			flag = os.O_RDWR
		}
		if !exists {
			flag |= os.O_CREATE | os.O_EXCL
		}
		if truncate {
			flag |= os.O_TRUNC
		}
		f, err := os.OpenFile(full, flag, 0o644)
		if err != nil {
			if writable || !exists {
				return fail(ntStatus(err, full))
			}
			f = nil // attribute-only access to an unreadable file
		}
		of.f = f
		of.writable = writable
		if !exists || truncate {
			d.written[p] = true
		}
		switch {
		case !exists:
			info = infoCreated
			d.emit(Event{Op: OpCreate, Path: p})
		case truncate && disposition == fileSupersede:
			info = infoSuperseded
		case truncate:
			info = infoOverwritten
		}
	}

	id := d.nextID
	d.nextID++
	d.files[id] = of
	return buildCompletion(req, statusSuccess, createTail(id, info))
}

func createTail(fileID uint32, info uint8) []byte {
	return append(u32Bytes(fileID), info)
}

func (d *Drive) close(req *IORequest) []byte {
	of := d.files[req.FileID]
	if of == nil {
		return buildCompletion(req, statusInvalidHandle, make([]byte, 5))
	}
	delete(d.files, req.FileID)
	if of.f != nil {
		_ = of.f.Close()
	}
	if of.read > 0 {
		d.emit(Event{Op: OpRead, Path: of.path, Bytes: of.read})
	}
	if of.written > 0 {
		d.emit(Event{Op: OpWrite, Path: of.path, Bytes: of.written})
	}
	status := uint32(statusSuccess)
	if of.deletePending && !d.ReadOnly {
		if err := os.Remove(of.full); err != nil {
			status = ntStatus(err, of.full)
		} else {
			delete(d.written, of.path)
			d.emit(Event{Op: OpDelete, Path: of.path})
		}
	}
	return buildCompletion(req, status, make([]byte, 5))
}

func (d *Drive) read(req *IORequest) []byte {
	r := newReader(req.Body)
	length := r.u32()
	offset := r.u64()
	of := d.files[req.FileID]
	switch {
	case of == nil:
		return buildCompletion(req, statusInvalidHandle, u32Bytes(0))
	case of.isDir || of.f == nil:
		return buildCompletion(req, statusInvalidDeviceRequest, u32Bytes(0))
	case d.WriteOnly && !d.written[of.path]:
		return buildCompletion(req, statusAccessDenied, u32Bytes(0))
	}
	if length > maxReadLength {
		length = maxReadLength
	}
	buf := make([]byte, length)
	n, err := of.f.ReadAt(buf, int64(offset))
	if err != nil && err != io.EOF {
		return buildCompletion(req, ntStatus(err, of.full), u32Bytes(0))
	}
	of.read += int64(n)
	return buildCompletion(req, statusSuccess, append(u32Bytes(uint32(n)), buf[:n]...))
}

func (d *Drive) write(req *IORequest) []byte {
	r := newReader(req.Body)
	length := r.u32()
	offset := r.u64()
	r.skip(20)
	data := r.bytes(int(length))
	of := d.files[req.FileID]
	tail := func(n int) []byte { return append(u32Bytes(uint32(n)), 0) }
	switch {
	case of == nil:
		return buildCompletion(req, statusInvalidHandle, tail(0))
	case of.isDir || of.f == nil:
		return buildCompletion(req, statusInvalidDeviceRequest, tail(0))
	case d.ReadOnly || !of.writable:
		return buildCompletion(req, statusAccessDenied, tail(0))
	}
	n, err := of.f.WriteAt(data, int64(offset))
	of.written += int64(n)
	if err != nil {
		return buildCompletion(req, ntStatus(err, of.full), tail(n))
	}
	return buildCompletion(req, statusSuccess, tail(n))
}

func (d *Drive) stat(of *openFile) (fs.FileInfo, error) {
	if of.f != nil {
		return of.f.Stat()
	}
	return os.Stat(of.full)
}

func (d *Drive) attributes(info fs.FileInfo) uint32 {
	if info.IsDir() {
		return attrDirectory
	}
	if d.ReadOnly {
		return attrArchive | attrReadOnly
	}
	return attrArchive
}

func (d *Drive) queryInformation(req *IORequest) []byte {
	class := newReader(req.Body).u32()
	of := d.files[req.FileID]
	if of == nil {
		return buildCompletion(req, statusInvalidHandle, u32Bytes(0))
	}
	info, err := d.stat(of)
	if err != nil {
		return buildCompletion(req, ntStatus(err, of.full), u32Bytes(0))
	}
	ft := fileTime(info.ModTime())
	p := &builder{}
	switch class {
	case fileBasicInformation:
		p.u64(ft)
		p.u64(ft)
		p.u64(ft)
		p.u64(ft)
		p.u32(d.attributes(info))
	case fileStandardInformation:
		p.u64(uint64(info.Size()))
		p.u64(uint64(info.Size()))
		p.u32(1) // NumberOfLinks
		p.u8(boolByte(of.deletePending))
		p.u8(boolByte(info.IsDir()))
	case fileAttributeTagInformation:
		p.u32(d.attributes(info))
		p.u32(0) // ReparseTag
	default:
		return buildCompletion(req, statusNotSupported, u32Bytes(0))
	}
	return buildCompletion(req, statusSuccess, lengthPrefixed(p.bytes()))
}

func (d *Drive) setInformation(req *IORequest) []byte {
	r := newReader(req.Body)
	class := r.u32()
	length := r.u32()
	r.skip(24)
	buf := r.bytes(int(length))
	tail := u32Bytes(length)

	of := d.files[req.FileID]
	if of == nil {
		return buildCompletion(req, statusInvalidHandle, tail)
	}
	if d.ReadOnly {
		return buildCompletion(req, statusAccessDenied, tail)
	}
	br := newReader(buf)
	var err error
	switch class {
	case fileBasicInformation:
		br.skip(8) // CreationTime
		access := br.u64()
		write := br.u64()
		change := br.u64()
		if change > write {
			write = change
		}
		if write != 0 {
			atime := time.Now()
			if access != 0 {
				atime = fromFileTime(access)
			}
			err = os.Chtimes(of.full, atime, fromFileTime(write))
		}
	case fileEndOfFileInformation, fileAllocationInformation:
		size := int64(br.u64())
		info, serr := d.stat(of)
		if serr != nil {
			err = serr
			break
		}
		// A smaller allocation truncates; a larger one only reserves space.
		if class == fileEndOfFileInformation || size < info.Size() {
			if of.f != nil {
				err = of.f.Truncate(size)
			} else {
				err = os.Truncate(of.full, size)
			}
		}
	case fileDispositionInformation:
		pending := true
		if length > 0 {
			pending = br.u8() != 0
		}
		if pending && of.isDir {
			if entries, derr := os.ReadDir(of.full); derr == nil && len(entries) > 0 {
				return buildCompletion(req, statusDirectoryNotEmpty, tail)
			}
		}
		of.deletePending = pending
	case fileRenameInformation:
		replace := br.u8() != 0
		br.skip(1) // RootDirectory
		target := cleanPath(decodeUTF16(br.bytes(int(br.u32()))))
		return buildCompletion(req, d.rename(of, target, replace), tail)
	}
	if err != nil {
		return buildCompletion(req, ntStatus(err, of.full), tail)
	}
	return buildCompletion(req, statusSuccess, tail)
}

func (d *Drive) rename(of *openFile, target string, replace bool) uint32 {
	if !validName(target) {
		return statusObjectNameInvalid
	}
	full, err := d.resolve(target)
	if err != nil {
		return statusAccessDenied
	}
	if _, err := os.Stat(full); err == nil && !replace {
		return statusObjectNameCollision
	}
	// Windows cannot rename a file that is open, so reopen it afterwards.
	if of.f != nil {
		_ = of.f.Close()
		of.f = nil
	}
	err = os.Rename(of.full, full)
	if err == nil {
		d.emit(Event{Op: OpRename, Path: of.path, NewPath: target})
		delete(d.written, target)
		if d.written[of.path] {
			delete(d.written, of.path)
			d.written[target] = true
		}
		of.path, of.full = target, full
	}
	if !of.isDir {
		flag := os.O_RDONLY
		if of.writable {
			flag = os.O_RDWR
		}
		if f, ferr := os.OpenFile(of.full, flag, 0); ferr == nil {
			of.f = f
		}
	}
	return ntStatus(err, full)
}

func (d *Drive) queryVolumeInformation(req *IORequest) []byte {
	class := newReader(req.Body).u32()
	total, free := diskSpace(d.root)
	const bytesPerSector, sectorsPerUnit = 512, 8
	const unit = bytesPerSector * sectorsPerUnit
	p := &builder{}
	switch class {
	case fileFsVolumeInformation:
		label := encodeUTF16(d.Name, true)
		var created uint64
		if st, err := os.Stat(d.root); err == nil {
			created = fileTime(st.ModTime())
		}
		p.u64(created)
		p.u32(0x47524450) // VolumeSerialNumber
		p.u32(uint32(len(label)))
		p.u8(0) // SupportsObjects
		p.raw(label)
	case fileFsSizeInformation:
		p.u64(total / unit)
		p.u64(free / unit)
		p.u32(sectorsPerUnit)
		p.u32(bytesPerSector)
	case fileFsFullSizeInformation:
		p.u64(total / unit)
		p.u64(free / unit)
		p.u64(free / unit)
		p.u32(sectorsPerUnit)
		p.u32(bytesPerSector)
	case fileFsAttributeInformation:
		name := encodeUTF16("NTFS", true)
		p.u32(0x00000001 | 0x00000002 | 0x00000004) // case-sensitive search, case-preserved, Unicode
		p.u32(255)                                  // MaximumComponentNameLength
		p.u32(uint32(len(name)))
		p.raw(name)
	case fileFsDeviceInformation:
		p.u32(0x00000007) // FILE_DEVICE_DISK
		if d.ReadOnly {
			p.u32(0x00000002) // FILE_READ_ONLY_DEVICE
		} else {
			p.u32(0)
		}
	default:
		return buildCompletion(req, statusNotSupported, u32Bytes(0))
	}
	return buildCompletion(req, statusSuccess, lengthPrefixed(p.bytes()))
}

func (d *Drive) directoryControl(req *IORequest) []byte {
	empty := append(u32Bytes(0), 0)
	if req.MinorFunction != irpMinorQueryDirectory {
		return buildCompletion(req, statusNotSupported, u32Bytes(0))
	}
	r := newReader(req.Body)
	class := r.u32()
	initial := r.u8() != 0
	pathLen := r.u32()
	r.skip(23)
	of := d.files[req.FileID]
	if of == nil {
		return buildCompletion(req, statusInvalidHandle, empty)
	}
	if initial {
		entries, err := d.list(cleanPath(decodeUTF16(r.bytes(int(pathLen)))))
		if err != nil {
			return buildCompletion(req, statusNoSuchFile, empty)
		}
		of.entries, of.next = entries, 0
	}
	if of.next >= len(of.entries) {
		status := uint32(statusNoMoreFiles)
		if initial {
			status = statusNoSuchFile
		}
		return buildCompletion(req, status, empty)
	}
	e := of.entries[of.next]
	name := encodeUTF16(e.name, false)
	ft := fileTime(e.info.ModTime())
	size := uint64(e.info.Size())
	if e.info.IsDir() {
		size = 0
	}
	p := &builder{}
	p.u32(0) // NextEntryOffset
	p.u32(0) // FileIndex
	if class != fileNamesInformation {
		p.u64(ft)
		p.u64(ft)
		p.u64(ft)
		p.u64(ft)
		p.u64(size) // EndOfFile
		p.u64(size) // AllocationSize
		p.u32(d.attributes(e.info))
	}
	p.u32(uint32(len(name)))
	switch class {
	case fileDirectoryInformation, fileNamesInformation:
	case fileFullDirectoryInformation:
		p.u32(0) // EaSize
	case fileBothDirectoryInformation:
		p.u32(0) // EaSize
		p.u8(0)  // ShortNameLength
		p.zero(24)
	default:
		return buildCompletion(req, statusNotSupported, empty)
	}
	p.raw(name)
	of.next++
	return buildCompletion(req, statusSuccess, lengthPrefixed(p.bytes()))
}

// list returns the entries of the directory part of pattern p (e.g.
// "/dir/*.txt") whose names match its last element, "." and ".." first.
func (d *Drive) list(p string) ([]dirEntry, error) {
	dir, pattern := path.Dir(p), path.Base(p)
	if p == "/" {
		dir, pattern = "/", "*"
	}
	full, err := d.resolve(dir)
	if err != nil {
		return nil, err
	}
	dirInfo, err := os.Stat(full)
	if err != nil {
		return nil, err
	}
	var out []dirEntry
	if dir != "/" {
		for _, n := range []string{".", ".."} {
			if wildcardMatch(pattern, n) {
				out = append(out, dirEntry{name: n, info: dirInfo})
			}
		}
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if !wildcardMatch(pattern, e.Name()) {
			continue
		}
		info, err := os.Stat(filepath.Join(full, e.Name()))
		if err != nil {
			continue
		}
		if real, err := filepath.EvalSymlinks(filepath.Join(full, e.Name())); err != nil || !within(d.root, real) {
			continue
		}
		out = append(out, dirEntry{name: e.Name(), info: info})
	}
	return out, nil
}

// wildcardMatch matches name against a Windows file pattern, case
// insensitively, including the DOS wildcards the redirector may send.
func wildcardMatch(pattern, name string) bool {
	pattern = strings.NewReplacer("<", "*", ">", "?", `"`, ".").Replace(pattern)
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	return globMatch([]rune(strings.ToLower(pattern)), []rune(strings.ToLower(name)))
}

func globMatch(p, s []rune) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := 0; i <= len(s); i++ {
				if globMatch(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
		default:
			if len(s) == 0 || s[0] != p[0] {
				return false
			}
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

// fileTime converts t to a Windows FILETIME (100 ns intervals since 1601).
func fileTime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

func fromFileTime(ft uint64) time.Time {
	return time.Unix(0, int64(ft-116444736000000000)*100)
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func u32Bytes(v uint32) []byte {
	return binary.LittleEndian.AppendUint32(nil, v)
}

func lengthPrefixed(b []byte) []byte {
	return append(u32Bytes(uint32(len(b))), b...)
}

// reader reads little-endian fields, yielding zero values past the end.
type reader struct{ b []byte }

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		n = len(r.b)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int)         { r.take(n) }
func (r *reader) bytes(n int) []byte { return r.take(n) }

func (r *reader) u8() byte {
	if v := r.take(1); len(v) == 1 {
		return v[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); len(v) == 4 {
		return binary.LittleEndian.Uint32(v)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if v := r.take(8); len(v) == 8 {
		return binary.LittleEndian.Uint64(v)
	}
	return 0
}
