package utils

import (
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend"
)

func GetHexArray(hexStr string, maxLen int) (res []frontend.Variable) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	for i := 0; i < maxLen; i++ {
		if i < len(hexStr) {
			intValue, _ := strconv.ParseInt(string(hexStr[i]), 16, 64)
			res = append(res, intValue)
		} else {
			res = append(res, 0)
		}
	}
	return
}
