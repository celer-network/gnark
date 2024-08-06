package keccaklookup

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/limbs"
	"github.com/consensys/gnark/std/mux"
)

type API struct {
	api frontend.API
	ka  *KeccakfAPI
	la  *limbs.API
	k   int // k is the limb size
}

// NewAPI initializes lookup tables for xor and chi step and returns the api instance
func NewAPI(api frontend.API, k int) *API {
	return &API{
		api: api,
		ka:  NewKeccakfAPI(api, k),
		la:  limbs.NewAPI(api),
		k:   k,
	}
}

// Keccak256 performs keccak256 on the input data and returns the hash. The input data must be padded before calling this function
// roundIndex is zero-based. e.g. roundIndex = 0 to select the output of the first round
// `inBitSize` declares the bit size of each `frontend.Variable` in `data`, which must ranged checked outside.
// `outBitSize` declares the wanted bit size of the returned hash
func (a *API) Keccak256(maxRounds, inBitSize, outBitSize int, roundIndex frontend.Variable, data []frontend.Variable) []frontend.Variable {
	roundSize := 1088 / inBitSize

	require(1088%inBitSize == 0, "input var size must divde 1088")
	require(1088%outBitSize == 0, "output var size must divde 1088")
	require(len(data)%roundSize == 0, "data length must be multiple of round size")
	require(len(data) <= maxRounds*roundSize, "data length too large")
	require(maxRounds > 0, "invalid maxRounds %d", maxRounds)

	var states [][25]limbs.Limbs
	// initial state
	states = append(states, a.newEmptyState())
	for i := 0; i < maxRounds; i++ {
		r := getRoundVars(data, i, inBitSize)
		bw := a.var2Lanes(r, inBitSize)
		s := a.absorb(states[i], bw)
		states = append(states, s)
	}
	ret := make([]frontend.Variable, 256/outBitSize)
	if maxRounds == 1 {
		hash := a.lanes2Vars(states[1][:4], outBitSize)
		checkLen(hash, 256/outBitSize)
		copy(ret[:], hash)
	} else {
		selected := mux.Multiplex(a.api, roundIndex, 4*(64/a.k), maxRounds, a.makeMatrixForMux(states[1:]))
		var hash []frontend.Variable
		for _, s := range selected {
			ws := a.la.Split(limbs.Limb{Val: s, Size: a.k}, outBitSize)
			hash = append(hash, ws.Values()...)
		}
		checkLen(hash, 256/outBitSize)
		copy(ret[:], hash)
	}
	return ret
}

func (a *API) absorb(s [25]limbs.Limbs, ls [17]limbs.Limbs) [25]limbs.Limbs {
	var newS [25]limbs.Limbs
	copy(newS[:], s[:])
	for i := 0; i < 17; i++ {
		newS[i] = a.ka.xor(s[i], ls[i])
	}
	return a.ka.Permute(newS)
}

func (a *API) makeMatrixForMux(in [][25]limbs.Limbs) [][]frontend.Variable {
	// we only need the first 4 lanes. e.g. if word size is 4, then we need 4 * (64 / 4) = 64 cols
	cols := 4 * (64 / a.k)
	rows := len(in)
	// flatten the words in each state lane
	var inf [][]limbs.Limb
	for i := 0; i < len(in); i++ {
		inf = append(inf, make([]limbs.Limb, 0))
		for j := 0; j < 4; j++ {
			inf[i] = append(inf[i], in[i][j]...)
		}
	}
	// transpose
	ret := make([][]frontend.Variable, cols)
	for i := 0; i < cols; i++ {
		ret[i] = make([]frontend.Variable, rows)
		for j := 0; j < rows; j++ {
			ret[i][j] = inf[j][i].Val
		}
	}
	return ret
}

func (a *API) var2Lanes(vars []frontend.Variable, size int) [17]limbs.Limbs {
	require(len(vars)*size == 1088, "invalid vars total size")
	s := 64 / size
	var lanes [17]limbs.Limbs
	for i := 0; i < 17; i++ {
		lanes[i] = a.var2Lane(vars[i*s:(i+1)*s], size)
	}
	return lanes
}

// var2Lane merges smaller chunks into chunks of size k to form a lane of total 64 bits
func (a *API) var2Lane(vars []frontend.Variable, size int) limbs.Limbs {
	require(size <= a.k, "cannot lane merge: var size %d > k %d", size, a.k)
	var lane limbs.Limbs
	for i := 0; i < 64; i += a.k {
		var ws limbs.Limbs
		for j := 0; j < a.k; j++ {
			ws = append(ws, limbs.Limb{Val: vars[i+j], Size: size})
		}
		lane = append(lane, a.la.Merge(ws))
	}
	return lane
}

func (a *API) lanes2Vars(lanes []limbs.Limbs, size int) []frontend.Variable {
	var ret []frontend.Variable
	for _, l := range lanes {
		ret = append(ret, a.lane2Vars(l, size)...)
	}
	return ret
}

// lane2Vars splits a lane into smaller chunks of `size`. `size` must be a divisor of k.
// Each word in `ws` must be of size a.k
func (a *API) lane2Vars(lane limbs.Limbs, size int) []frontend.Variable {
	checkLen(lane, 64/a.k)
	var ret []frontend.Variable
	for _, w := range lane {
		require(w.Size == a.k, "word size %d != k %d", w.Size, a.k)
		res := a.la.Split(w, size)
		for _, b := range res {
			ret = append(ret, b.Val)
		}
	}
	return ret
}

func (a *API) newEmptyState() [25]limbs.Limbs {
	var s [25]limbs.Limbs
	for i := 0; i < 25; i++ {
		var lane limbs.Limbs
		for j := 0; j < 64/a.k; j++ {
			lane = append(lane, limbs.Limb{Val: 0, Size: a.k})
		}
		s[i] = lane
	}
	return s
}

func getRoundVars(data []frontend.Variable, round int, size int) []frontend.Variable {
	roundSize := 1088 / size
	return data[round*roundSize : (round+1)*roundSize]
}
