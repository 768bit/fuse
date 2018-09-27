// +build !windows

// See the file LICENSE for copyright and licensing information.

// Adapted from Plan 9 from User Space's src/cmd/9pfuse/fuse.c,
// which carries this notice:
//
// The files in this directory are subject to the following license.
//
// The author of this software is Russ Cox.
//
//         Copyright (c) 2006 Russ Cox
//
// Permission to use, copy, modify, and distribute this software for any
// purpose without fee is hereby granted, provided that this entire notice
// is included in all copies of any software which is or includes a copy
// or modification of this software and in all copies of the supporting
// documentation for such software.
//
// THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTY.  IN PARTICULAR, THE AUTHOR MAKES NO REPRESENTATION OR WARRANTY
// OF ANY KIND CONCERNING THE MERCHANTABILITY OF THIS SOFTWARE OR ITS
// FITNESS FOR ANY PARTICULAR PURPOSE.

// Package fuse enables writing FUSE file systems on Linux, OS X, and FreeBSD.
//
// On OS X, it requires OSXFUSE (http://osxfuse.github.com/).
//
// There are two approaches to writing a FUSE file system.  The first is to speak
// the low-level message protocol, reading from a Conn using ReadRequest and
// writing using the various Respond methods.  This approach is closest to
// the actual interaction with the kernel and can be the simplest one in contexts
// such as protocol translators.
//
// Servers of synthesized file systems tend to share common
// bookkeeping abstracted away by the second approach, which is to
// call fs.Serve to serve the FUSE protocol using an implementation of
// the service methods in the interfaces FS* (file system), Node* (file
// or directory), and Handle* (opened file or directory).
// There are a daunting number of such methods that can be written,
// but few are required.
// The specific methods are described in the documentation for those interfaces.
//
// The hellofs subdirectory contains a simple illustration of the fs.Serve approach.
//
// Service Methods
//
// The required and optional methods for the FS, Node, and Handle interfaces
// have the general form
//
//	Op(ctx context.Context, req *OpRequest, resp *OpResponse) error
//
// where Op is the name of a FUSE operation. Op reads request
// parameters from req and writes results to resp. An operation whose
// only result is the error result omits the resp parameter.
//
// Multiple goroutines may call service methods simultaneously; the
// methods being called are responsible for appropriate
// synchronization.
//
// The operation must not hold on to the request or response,
// including any []byte fields such as WriteRequest.Data or
// SetxattrRequest.Xattr.
//
// Errors
//
// Operations can return errors. The FUSE interface can only
// communicate POSIX errno error numbers to file system clients, the
// message is not visible to file system clients. The returned error
// can implement ErrorNumber to control the errno returned. Without
// ErrorNumber, a generic errno (EIO) is returned.
//
// Error messages will be visible in the debug log as part of the
// response.
//
// Interrupted Operations
//
// In some file systems, some operations
// may take an undetermined amount of time.  For example, a Read waiting for
// a network message or a matching Write might wait indefinitely.  If the request
// is cancelled and no longer needed, the context will be cancelled.
// Blocking operations should select on a receive from ctx.Done() and attempt to
// abort the operation early if the receive succeeds (meaning the channel is closed).
// To indicate that the operation failed because it was aborted, return fuse.EINTR.
//
// If an operation does not block for an indefinite amount of time, supporting
// cancellation is not necessary.
//
// Authentication
//
// All requests types embed a Header, meaning that the method can
// inspect req.Pid, req.Uid, and req.Gid as necessary to implement
// permission checking. The kernel FUSE layer normally prevents other
// users from accessing the FUSE file system (to change this, see
// AllowOther, AllowRoot), but does not enforce access modes (to
// change this, see DefaultPermissions).
//
// Mount Options
//
// Behavior and metadata of the mounted file system can be changed by
// passing MountOption values to Mount.
//
package fuse // import "gitlab.768bit.com/vann/fuse"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// ReadRequest returns the next FUSE request from the kernel.
//
// Caller must call either Request.Respond or Request.RespondError in
// a reasonable time. Caller must not retain Request after that call.
func (c *Conn) ReadRequest() (Request, error) {
	m := getMessage(c)
loop:
	c.rio.RLock()
	n, err := syscall.Read(c.fd(), m.buf)
	c.rio.RUnlock()
	if err == syscall.EINTR {
		// OSXFUSE sends EINTR to userspace when a request interrupt
		// completed before it got sent to userspace?
		goto loop
	}
	if err != nil && err != syscall.ENODEV {
		putMessage(m)
		return nil, err
	}
	if n <= 0 {
		putMessage(m)
		return nil, io.EOF
	}
	m.buf = m.buf[:n]

	if n < inHeaderSize {
		putMessage(m)
		return nil, errors.New("fuse: message too short")
	}

	// FreeBSD FUSE sends a short length in the header
	// for FUSE_INIT even though the actual read length is correct.
	if n == inHeaderSize+initInSize && m.hdr.Opcode == opInit && m.hdr.Len < uint32(n) {
		m.hdr.Len = uint32(n)
	}

	// OSXFUSE sometimes sends the wrong m.hdr.Len in a FUSE_WRITE message.
	if m.hdr.Len < uint32(n) && m.hdr.Len >= uint32(unsafe.Sizeof(writeIn{})) && m.hdr.Opcode == opWrite {
		m.hdr.Len = uint32(n)
	}

	if m.hdr.Len != uint32(n) {
		// prepare error message before returning m to pool
		err := fmt.Errorf("fuse: read %d opcode %d but expected %d", n, m.hdr.Opcode, m.hdr.Len)
		putMessage(m)
		return nil, err
	}

	m.off = inHeaderSize

	// Convert to data structures.
	// Do not trust kernel to hand us well-formed data.
	var req Request
	switch m.hdr.Opcode {
	default:
		Debug(noOpcode{Opcode: m.hdr.Opcode})
		goto unrecognized

	case opLookup:
		buf := m.bytes()
		n := len(buf)
		if n == 0 || buf[n-1] != '\x00' {
			goto corrupt
		}
		req = &LookupRequest{
			Header: m.Header(),
			Name:   string(buf[:n-1]),
		}

	case opForget:
		in := (*forgetIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &ForgetRequest{
			Header: m.Header(),
			N:      in.Nlookup,
		}

	case opGetattr:
		switch {
		case c.proto.LT(Protocol{7, 9}):
			req = &GetattrRequest{
				Header: m.Header(),
			}

		default:
			in := (*getattrIn)(m.data())
			if m.len() < unsafe.Sizeof(*in) {
				goto corrupt
			}
			req = &GetattrRequest{
				Header: m.Header(),
				Flags:  GetattrFlags(in.GetattrFlags),
				Handle: HandleID(in.Fh),
			}
		}

	case opSetattr:
		in := (*setattrIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &SetattrRequest{
			Header:   m.Header(),
			Valid:    SetattrValid(in.Valid),
			Handle:   HandleID(in.Fh),
			Size:     in.Size,
			Atime:    time.Unix(int64(in.Atime), int64(in.AtimeNsec)),
			Mtime:    time.Unix(int64(in.Mtime), int64(in.MtimeNsec)),
			Mode:     fileMode(in.Mode),
			Uid:      in.Uid,
			Gid:      in.Gid,
			Bkuptime: in.BkupTime(),
			Chgtime:  in.Chgtime(),
			Flags:    in.Flags(),
		}

	case opReadlink:
		if len(m.bytes()) > 0 {
			goto corrupt
		}
		req = &ReadlinkRequest{
			Header: m.Header(),
		}

	case opSymlink:
		// m.bytes() is "newName\0target\0"
		names := m.bytes()
		if len(names) == 0 || names[len(names)-1] != 0 {
			goto corrupt
		}
		i := bytes.IndexByte(names, '\x00')
		if i < 0 {
			goto corrupt
		}
		newName, target := names[0:i], names[i+1:len(names)-1]
		req = &SymlinkRequest{
			Header:  m.Header(),
			NewName: string(newName),
			Target:  string(target),
		}

	case opLink:
		in := (*linkIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		newName := m.bytes()[unsafe.Sizeof(*in):]
		if len(newName) < 2 || newName[len(newName)-1] != 0 {
			goto corrupt
		}
		newName = newName[:len(newName)-1]
		req = &LinkRequest{
			Header:  m.Header(),
			OldNode: NodeID(in.Oldnodeid),
			NewName: string(newName),
		}

	case opMknod:
		size := mknodInSize(c.proto)
		if m.len() < size {
			goto corrupt
		}
		in := (*mknodIn)(m.data())
		name := m.bytes()[size:]
		if len(name) < 2 || name[len(name)-1] != '\x00' {
			goto corrupt
		}
		name = name[:len(name)-1]
		r := &MknodRequest{
			Header: m.Header(),
			Mode:   fileMode(in.Mode),
			Rdev:   in.Rdev,
			Name:   string(name),
		}
		if c.proto.GE(Protocol{7, 12}) {
			r.Umask = fileMode(in.Umask) & os.ModePerm
		}
		req = r

	case opMkdir:
		size := mkdirInSize(c.proto)
		if m.len() < size {
			goto corrupt
		}
		in := (*mkdirIn)(m.data())
		name := m.bytes()[size:]
		i := bytes.IndexByte(name, '\x00')
		if i < 0 {
			goto corrupt
		}
		r := &MkdirRequest{
			Header: m.Header(),
			Name:   string(name[:i]),
			// observed on Linux: mkdirIn.Mode & syscall.S_IFMT == 0,
			// and this causes fileMode to go into it's "no idea"
			// code branch; enforce type to directory
			Mode: fileMode((in.Mode &^ syscall.S_IFMT) | syscall.S_IFDIR),
		}
		if c.proto.GE(Protocol{7, 12}) {
			r.Umask = fileMode(in.Umask) & os.ModePerm
		}
		req = r

	case opUnlink, opRmdir:
		buf := m.bytes()
		n := len(buf)
		if n == 0 || buf[n-1] != '\x00' {
			goto corrupt
		}
		req = &RemoveRequest{
			Header: m.Header(),
			Name:   string(buf[:n-1]),
			Dir:    m.hdr.Opcode == opRmdir,
		}

	case opRename:
		in := (*renameIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		newDirNodeID := NodeID(in.Newdir)
		oldNew := m.bytes()[unsafe.Sizeof(*in):]
		// oldNew should be "old\x00new\x00"
		if len(oldNew) < 4 {
			goto corrupt
		}
		if oldNew[len(oldNew)-1] != '\x00' {
			goto corrupt
		}
		i := bytes.IndexByte(oldNew, '\x00')
		if i < 0 {
			goto corrupt
		}
		oldName, newName := string(oldNew[:i]), string(oldNew[i+1:len(oldNew)-1])
		req = &RenameRequest{
			Header:  m.Header(),
			NewDir:  newDirNodeID,
			OldName: oldName,
			NewName: newName,
		}

	case opOpendir, opOpen:
		in := (*openIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &OpenRequest{
			Header: m.Header(),
			Dir:    m.hdr.Opcode == opOpendir,
			Flags:  openFlags(in.Flags),
		}

	case opRead, opReaddir:
		in := (*readIn)(m.data())
		if m.len() < readInSize(c.proto) {
			goto corrupt
		}
		r := &ReadRequest{
			Header: m.Header(),
			Dir:    m.hdr.Opcode == opReaddir,
			Handle: HandleID(in.Fh),
			Offset: int64(in.Offset),
			Size:   int(in.Size),
		}
		if c.proto.GE(Protocol{7, 9}) {
			r.Flags = ReadFlags(in.ReadFlags)
			r.LockOwner = in.LockOwner
			r.FileFlags = openFlags(in.Flags)
		}
		req = r

	case opWrite:
		in := (*writeIn)(m.data())
		if m.len() < writeInSize(c.proto) {
			goto corrupt
		}
		r := &WriteRequest{
			Header: m.Header(),
			Handle: HandleID(in.Fh),
			Offset: int64(in.Offset),
			Flags:  WriteFlags(in.WriteFlags),
		}
		if c.proto.GE(Protocol{7, 9}) {
			r.LockOwner = in.LockOwner
			r.FileFlags = openFlags(in.Flags)
		}
		buf := m.bytes()[writeInSize(c.proto):]
		if uint32(len(buf)) < in.Size {
			goto corrupt
		}
		r.Data = buf
		req = r

	case opStatfs:
		req = &StatfsRequest{
			Header: m.Header(),
		}

	case opRelease, opReleasedir:
		in := (*releaseIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &ReleaseRequest{
			Header:       m.Header(),
			Dir:          m.hdr.Opcode == opReleasedir,
			Handle:       HandleID(in.Fh),
			Flags:        openFlags(in.Flags),
			ReleaseFlags: ReleaseFlags(in.ReleaseFlags),
			LockOwner:    in.LockOwner,
		}

	case opFsync, opFsyncdir:
		in := (*fsyncIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &FsyncRequest{
			Dir:    m.hdr.Opcode == opFsyncdir,
			Header: m.Header(),
			Handle: HandleID(in.Fh),
			Flags:  in.FsyncFlags,
		}

	case opSetxattr:
		in := (*setxattrIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		m.off += int(unsafe.Sizeof(*in))
		name := m.bytes()
		i := bytes.IndexByte(name, '\x00')
		if i < 0 {
			goto corrupt
		}
		xattr := name[i+1:]
		if uint32(len(xattr)) < in.Size {
			goto corrupt
		}
		xattr = xattr[:in.Size]
		req = &SetxattrRequest{
			Header:   m.Header(),
			Flags:    in.Flags,
			Position: in.position(),
			Name:     string(name[:i]),
			Xattr:    xattr,
		}

	case opGetxattr:
		in := (*getxattrIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		name := m.bytes()[unsafe.Sizeof(*in):]
		i := bytes.IndexByte(name, '\x00')
		if i < 0 {
			goto corrupt
		}
		req = &GetxattrRequest{
			Header:   m.Header(),
			Name:     string(name[:i]),
			Size:     in.Size,
			Position: in.position(),
		}

	case opListxattr:
		in := (*getxattrIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &ListxattrRequest{
			Header:   m.Header(),
			Size:     in.Size,
			Position: in.position(),
		}

	case opRemovexattr:
		buf := m.bytes()
		n := len(buf)
		if n == 0 || buf[n-1] != '\x00' {
			goto corrupt
		}
		req = &RemovexattrRequest{
			Header: m.Header(),
			Name:   string(buf[:n-1]),
		}

	case opFlush:
		in := (*flushIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &FlushRequest{
			Header:    m.Header(),
			Handle:    HandleID(in.Fh),
			Flags:     in.FlushFlags,
			LockOwner: in.LockOwner,
		}

	case opInit:
		in := (*initIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &InitRequest{
			Header:       m.Header(),
			Kernel:       Protocol{in.Major, in.Minor},
			MaxReadahead: in.MaxReadahead,
			Flags:        InitFlags(in.Flags),
		}

	case opGetlk:
		panic("opGetlk")
	case opSetlk:
		panic("opSetlk")
	case opSetlkw:
		panic("opSetlkw")

	case opAccess:
		in := (*accessIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &AccessRequest{
			Header: m.Header(),
			Mask:   in.Mask,
		}

	case opCreate:
		size := createInSize(c.proto)
		if m.len() < size {
			goto corrupt
		}
		in := (*createIn)(m.data())
		name := m.bytes()[size:]
		i := bytes.IndexByte(name, '\x00')
		if i < 0 {
			goto corrupt
		}
		r := &CreateRequest{
			Header: m.Header(),
			Flags:  openFlags(in.Flags),
			Mode:   fileMode(in.Mode),
			Name:   string(name[:i]),
		}
		if c.proto.GE(Protocol{7, 12}) {
			r.Umask = fileMode(in.Umask) & os.ModePerm
		}
		req = r

	case opInterrupt:
		in := (*interruptIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		req = &InterruptRequest{
			Header: m.Header(),
			IntrID: RequestID(in.Unique),
		}

	case opBmap:
		panic("opBmap")

	case opDestroy:
		req = &DestroyRequest{
			Header: m.Header(),
		}

		// OS X
	case opSetvolname:
		panic("opSetvolname")
	case opGetxtimes:
		panic("opGetxtimes")
	case opExchange:
		in := (*exchangeIn)(m.data())
		if m.len() < unsafe.Sizeof(*in) {
			goto corrupt
		}
		oldDirNodeID := NodeID(in.Olddir)
		newDirNodeID := NodeID(in.Newdir)
		oldNew := m.bytes()[unsafe.Sizeof(*in):]
		// oldNew should be "oldname\x00newname\x00"
		if len(oldNew) < 4 {
			goto corrupt
		}
		if oldNew[len(oldNew)-1] != '\x00' {
			goto corrupt
		}
		i := bytes.IndexByte(oldNew, '\x00')
		if i < 0 {
			goto corrupt
		}
		oldName, newName := string(oldNew[:i]), string(oldNew[i+1:len(oldNew)-1])
		req = &ExchangeDataRequest{
			Header:  m.Header(),
			OldDir:  oldDirNodeID,
			NewDir:  newDirNodeID,
			OldName: oldName,
			NewName: newName,
			// TODO options
		}
	}

	return req, nil

corrupt:
	Debug(malformedMessage{})
	putMessage(m)
	return nil, fmt.Errorf("fuse: malformed message")

unrecognized:
	// Unrecognized message.
	// Assume higher-level code will send a "no idea what you mean" error.
	h := m.Header()
	return &h, nil
}

// MountpointDoesNotExistError is an error returned when the
// mountpoint does not exist.
type MountpointDoesNotExistError struct {
	Path string
}

var _ error = (*MountpointDoesNotExistError)(nil)

func (e *MountpointDoesNotExistError) Error() string {
	return fmt.Sprintf("mountpoint does not exist: %v", e.Path)
}

// Mount mounts a new FUSE connection on the named directory
// and returns a connection for reading and writing FUSE messages.
//
// After a successful return, caller must call Close to free
// resources.
//
// Even on successful return, the new mount is not guaranteed to be
// visible until after Conn.Ready is closed. See Conn.MountError for
// possible errors. Incoming requests on Conn must be served to make
// progress.
func Mount(dir string, options ...MountOption) (*Conn, error) {
	conf := mountConfig{
		options: make(map[string]string),
	}
	for _, option := range options {
		if err := option(&conf); err != nil {
			return nil, err
		}
	}

	ready := make(chan struct{}, 1)
	c := &Conn{
		Ready: ready,
	}
	f, err := mount(dir, &conf, ready, &c.MountError)
	if err != nil {
		return nil, err
	}
	c.dev = f

	if err := initMount(c, &conf); err != nil {
		c.Close()
		if err == ErrClosedWithoutInit {
			// see if we can provide a better error
			<-c.Ready
			if err := c.MountError; err != nil {
				return nil, err
			}
		}
		return nil, err
	}

	return c, nil
}

type OldVersionError struct {
	Kernel     Protocol
	LibraryMin Protocol
}

func (e *OldVersionError) Error() string {
	return fmt.Sprintf("kernel FUSE version is too old: %v < %v", e.Kernel, e.LibraryMin)
}

var (
	ErrClosedWithoutInit = errors.New("fuse connection closed without init")
)

func initMount(c *Conn, conf *mountConfig) error {
	req, err := c.ReadRequest()
	if err != nil {
		if err == io.EOF {
			return ErrClosedWithoutInit
		}
		return err
	}
	r, ok := req.(*InitRequest)
	if !ok {
		return fmt.Errorf("missing init, got: %T", req)
	}

	min := Protocol{protoVersionMinMajor, protoVersionMinMinor}
	if r.Kernel.LT(min) {
		req.RespondError(Errno(syscall.EPROTO))
		c.Close()
		return &OldVersionError{
			Kernel:     r.Kernel,
			LibraryMin: min,
		}
	}

	proto := Protocol{protoVersionMaxMajor, protoVersionMaxMinor}
	if r.Kernel.LT(proto) {
		// Kernel doesn't support the latest version we have.
		proto = r.Kernel
	}
	c.proto = proto

	s := &InitResponse{
		Library:      proto,
		MaxReadahead: conf.maxReadahead,
		MaxWrite:     maxWrite,
		Flags:        InitBigWrites | conf.initFlags,
	}
	r.Respond(s)
	return nil
}
