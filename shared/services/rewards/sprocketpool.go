package rewards

import (
	"runtime"

	"github.com/rocket-pool/smartnode/shared/services/beacon"
)

type epochState struct {
	duringInterval bool
	epoch          uint64
	committees     beacon.Committees
	attestations   [][]beacon.AttestationInfo
	withdrawals    map[uint64][]beacon.WithdrawalInfo
}

func getWorkerCount() uint64 {
	nproc := runtime.NumCPU()

	target := nproc - 2
	if target < 1 {
		return 1
	}

	return uint64(target)
}
