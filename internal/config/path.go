package config

import (
	"os"
	"path/filepath"
)

type UploadPaths struct {
	Base    string
	Zips    string
	Results string
}

func NewUploadPaths(base string) UploadPaths {
	return UploadPaths{
		Base:    base,
		Zips:    filepath.Join(base, "zips"),
		Results: filepath.Join(base, "results"),
	}
}

func (p UploadPaths) Ensure() error {
	if err := os.MkdirAll(p.Zips, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(p.Results, 0o755); err != nil {
		return err
	}
	return nil
}
