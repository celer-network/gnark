package limbs

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
)

type Limb struct {
	Val  frontend.Variable `json:"val,omitempty"`
	Size int               `json:"size,omitempty"`
}

type Limbs []Limb

func (ws Limbs) Values() []frontend.Variable {
	var ret []frontend.Variable
	for _, w := range ws {
		ret = append(ret, w.Val)
	}
	return ret
}

func (ws Limbs) String() string {
	var strs []string
	for _, w := range ws {
		strs = append(strs, fmt.Sprintf("%x", w.Val))
	}
	return strings.Join(strs, "")
}

func (ws Limbs) totalSize() int {
	var total int
	for _, w := range ws {
		total += w.Size
	}
	return total
}

type API struct {
	api frontend.API
}

func NewAPI(api frontend.API) *API {
	return &API{api: api}
}

// Split splits the word into parts of `limbSize` execept the last element.
// this function uses a hint function to compute the Split results, then constrains the sum.
// nbLimbs is the number of equal sized parts of `limbSize`. optional, if not specified, the word is Split into as many
// `limbSize` chunks as possible.
// e.g. for word 1010 if `limbSize = 1` and `nbLimbsOpt = 2` then the result is [1, 0, 10]
func (a *API) Split(l Limb, limbSize int, nbLimbsOpt ...int) Limbs {
	if len(nbLimbsOpt) > 1 {
		log.Panicf("invalid nbLimbsOpt")
	}
	nbLimbs := l.Size / limbSize
	if len(nbLimbsOpt) == 1 {
		nbLimbs = nbLimbsOpt[0]
	}
	if nbLimbs <= 0 || nbLimbs > l.Size {
		panic(fmt.Sprintf("cannot split word of size %d into %d parts", l.Size, nbLimbs))
	}
	remSize := l.Size - nbLimbs*limbSize
	nbTotal := nbLimbs
	if remSize > 0 {
		nbTotal++
	}
	out, err := a.api.Compiler().NewHint(SplitHint, nbTotal, l.Val, l.Size, limbSize, nbLimbs)
	if err != nil {
		panic(fmt.Sprintf("hint failed to split merge output: %s", err.Error()))
	}
	var ret Limbs
	var acc frontend.Variable = 0
	nbZeros := l.Size
	for i := 0; i < nbLimbs; i++ {
		nbZeros -= limbSize
		acc = a.api.MulAcc(acc, out[i], exp2(nbZeros))
		ret = append(ret, Limb{Val: out[i], Size: limbSize})
	}
	if remSize > 0 {
		acc = a.api.Add(acc, out[len(out)-1])
		ret = append(ret, Limb{Val: out[len(out)-1], Size: remSize})
	}
	a.api.AssertIsEqual(acc, l.Val)
	return ret
}

func (wa *API) Merge(ws Limbs) Limb {
	if len(ws) < 1 {
		panic("cannot merge words with length less than 1")
	}
	var acc frontend.Variable = 0
	totalSize := ws.totalSize()
	nbZeros := totalSize
	for i := range ws {
		nbZeros -= ws[i].Size
		acc = wa.api.MulAcc(acc, ws[i].Val, exp2(nbZeros))
	}
	return Limb{
		Val:  acc,
		Size: ws.totalSize(),
	}
}

func (wa *API) Lrot(ws Limbs, amount, limbSize int) Limbs {
	rotated := wa.LrotMerge(ws, amount)
	return wa.Split(rotated, limbSize)
}

func (wa *API) LrotMerge(ws Limbs, amount int) Limb {
	i := 0
	rem := amount
	// search for where to split the word
	for ; i < len(ws); i++ {
		w := ws[i]
		if rem < w.Size {
			break
		}
		rem -= w.Size
	}

	// rotate the slice without splitting first
	rotated := make(Limbs, len(ws))
	copy(rotated[len(ws)-i:], ws[:i])
	copy(rotated, ws[i:])

	// split if needed
	if rem > 0 {
		parts := wa.Split(ws[i], rem, 1)
		// sanity check
		if len(parts) != 2 {
			log.Panicf("invalid parts len %d", len(parts))
		}
		rotated = append(rotated, parts[0])
		rotated[0] = parts[1]
	}
	return wa.Merge(rotated)
}

func exp2(num int) *big.Int {
	base := big.NewInt(2)
	exp := big.NewInt(int64(num))
	return new(big.Int).Exp(base, exp, nil)
}

func SplitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("split hint requires exactly 4 input params")
	}
	rem := inputs[0]
	remSize := int(inputs[1].Int64())
	limbSize := int(inputs[2].Int64())
	nbLimbs := int(inputs[3].Int64())
	for i := 0; i < nbLimbs; i++ {
		remSize -= limbSize
		zeros := exp2(remSize)
		quo := new(big.Int).Div(rem, zeros)
		outputs[i] = quo
		rem = new(big.Int).Sub(rem, new(big.Int).Mul(quo, zeros))
	}
	if remSize > 0 {
		outputs[len(outputs)-1] = rem
	}
	return nil
}
