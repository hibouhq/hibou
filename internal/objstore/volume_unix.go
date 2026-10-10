//go:build linux || darwin || freebsd

package objstore

import "syscall"

// volumeStats reports the filesystem holding path. Free is what an
// unprivileged process can still write (Bavail), not the root reserve.
func volumeStats(path string) (VolumeStats, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return VolumeStats{}, false
	}
	//nolint:unconvert // Bsize is int64 on linux but uint32 on darwin.
	bsize := int64(st.Bsize) // #nosec G115 -- block sizes are small positive values
	return VolumeStats{
		CapacityBytes: int64(st.Blocks) * bsize, // #nosec G115 -- block counts fit int64 for any real volume
		FreeBytes:     int64(st.Bavail) * bsize, // #nosec G115 -- block counts fit int64 for any real volume
	}, true
}
