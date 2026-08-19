//go:build !unix

package server

func processCPUSeconds() (float64, bool) { return 0, false }

func processRSSBytes() (int64, bool) { return 0, false }
