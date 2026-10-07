//go:build !linux

// Package initproc lets the binary act as a minimal init when it runs as PID 1.
// Only Linux containers run the binary as PID 1, so elsewhere it does nothing.
package initproc

// SuperviseIfPID1 is a no-op outside Linux.
func SuperviseIfPID1() {}
