// +build !windows

package util

func isPacketTooBig(err error) bool {
	return false
}
