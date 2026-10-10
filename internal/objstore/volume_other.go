//go:build !(linux || darwin || freebsd)

package objstore

func volumeStats(string) (VolumeStats, bool) { return VolumeStats{}, false }
