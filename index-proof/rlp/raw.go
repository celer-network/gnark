package rlp

import "github.com/consensys/gnark/frontend"

func LessThan(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Add(api.Cmp(a, b), 1))
}
