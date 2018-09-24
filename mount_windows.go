package fuse

import (
	"os"
)

func mount(dir string, conf *mountConfig, ready chan<- struct{}, errp *error) (fusefd *os.File, err error) {
	return nil, nil
}
