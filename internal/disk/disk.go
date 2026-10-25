// Package disk reports free space on the card and recognises a write that
// failed because the card is full.
package disk

// Free returns the bytes this user may still write in dir.
func Free(dir string) (int64, error) {
	free, _, err := Usage(dir)
	return free, err
}

// defaultCluster stands in when the filesystem does not report its
// allocation unit: 128 KiB is the largest exFAT uses on SD cards.
const defaultCluster = 128 << 10

func sane(cluster int64) int64 {
	if cluster < 512 || cluster > 32<<20 {
		return defaultCluster
	}
	return cluster
}
