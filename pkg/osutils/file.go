package osutils

import (
	"os"
	"path/filepath"
)

func MkDir(path string) error {
	dirPath := filepath.Dir(path)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err = os.MkdirAll(dirPath, os.ModePerm); err != nil {
			return err
		}
	}
	return nil
}
