// +build !windows

package fs

// Serve serves the FUSE connection by making calls to the methods
// of fs and the Nodes and Handles it makes available.  It returns only
// when the connection has been closed or an unexpected error occurs.
func (s *Server) Serve(fs FS) error {
	defer s.wg.Wait() // Wait for worker goroutines to complete before return

	s.fs = fs
	if dyn, ok := fs.(FSInodeGenerator); ok {
		s.dynamicInode = dyn.GenerateInode
	}

	root, err := fs.Root()
	if err != nil {
		return fmt.Errorf("cannot obtain root node: %v", err)
	}
	// Recognize the root node if it's ever returned from Lookup,
	// passed to Invalidate, etc.
	s.nodeRef[root] = 1
	s.node = append(s.node, nil, &serveNode{
		inode:      1,
		generation: s.nodeGen,
		node:       root,
		refs:       1,
	})
	s.handle = append(s.handle, nil)

	for {
		req, err := s.conn.ReadRequest()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(req)
		}()
	}
	return nil
}
