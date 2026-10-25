package vault

import (
	"errors"
	"fmt"
	"runtime"

	"sd-vault/internal/disk"
)

// ErrNoSpace means a write would not fit on the card.
var ErrNoSpace = errors.New("на карте не хватает места")

const (
	// ageHeader bounds the header of an age file for one X25519 recipient
	// (about 170 bytes) plus the payload nonce.
	ageHeader = 256
	// ageChunk is age's plaintext chunk; each one gains a 16-byte tag.
	ageChunk = 64 << 10
	// indexEntry bounds one entry of the JSON index, with a long name.
	indexEntry = 384
	// spaceMargin is left free on top of the estimate.
	spaceMargin = 1 << 20
)

// Space is what storing some files takes on the card and what is free there.
type Space struct {
	Need int64 `json:"need"`
	Free int64 `json:"free"`
}

// Fits reports whether the files fit.
func (s Space) Fits() bool { return s.Free >= s.Need }

// Err is nil when the files fit and an ErrNoSpace with the numbers when not.
func (s Space) Err() error {
	if s.Fits() {
		return nil
	}
	return fmt.Errorf("%w: нужно %s, свободно %s", ErrNoSpace, Megabytes(s.Need), Megabytes(s.Free))
}

// Megabytes formats n bytes for a message.
func Megabytes(n int64) string {
	return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
}

// Room estimates the space a batch upload (PutDeferred) of files with the
// given sizes takes, on top of what is pending, and reads what is free.
//
// The estimate errs on the large side. It counts the encryption overhead,
// the cluster each file's tail rounds up to (128 KiB on a big exFAT card),
// the "._" file macOS adds next to every file it creates on FAT, and room
// for the index the batch ends with. That last part matters most: a batch
// is listed only once its index is written, so a card filled to the last
// byte by content would lose the whole batch. Replaced files free their
// space only after that write, so they are not counted as freed.
func (v *Vault) Room(sizes []int64) (Space, error) {
	usage := v.DiskUsage
	if usage == nil {
		usage = disk.Usage
	}
	free, cluster, err := usage(v.dir)
	if err != nil {
		return Space{}, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.check(); err != nil {
		return Space{}, err
	}
	var perFile int64 // what every new file on the card adds
	if runtime.GOOS == "darwin" {
		perFile = cluster
	}
	onCard := func(plain int64) int64 {
		return roundUp(encryptedSize(plain), cluster) + perFile
	}

	// The new index is written next to the old one and its backup.
	need := int64(spaceMargin) + onCard(int64(len(v.idx.Entries)+len(sizes))*indexEntry)

	var small, packs int64
	if v.open != nil {
		small = int64(len(v.open.buf))
	}
	for _, n := range sizes {
		if n > packFileMax {
			need += onCard(n)
		} else {
			small += n
		}
	}
	if small > 0 {
		packs = (small + packMax - 1) / packMax
		need += roundUp(encryptedSize(small)+packs*ageHeader, cluster) + packs*(cluster+perFile)
	}
	return Space{Need: need, Free: free}, nil
}

// encryptedSize is the size of an age file holding n bytes.
func encryptedSize(n int64) int64 {
	chunks := (n + ageChunk - 1) / ageChunk
	if chunks == 0 {
		chunks = 1
	}
	return ageHeader + n + 16*chunks
}

func roundUp(n, unit int64) int64 {
	return (n + unit - 1) / unit * unit
}
