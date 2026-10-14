//go:build !windows && !unix

package securefile

import "os"

func checkPlatformPath(string) error             { return ErrUnsafe }
func checkNoReparse(string) error                { return ErrUnsafe }
func makePrivateDir(string) error                { return ErrUnsafe }
func checkPrivateDirectory(string) error         { return ErrUnsafe }
func createPrivateFile(string) (*os.File, error) { return nil, ErrUnsafe }
func openPrivateFile(string) (*os.File, error)   { return nil, ErrUnsafe }
