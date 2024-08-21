package main

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaulAdminPass(t *testing.T) {
	salt := "haidu#41312#gohk"
	saltedPass := "admin" + salt
	sha_512 := sha512.New()
	sha_512.Write([]byte(saltedPass))

	passwordHash := hex.EncodeToString(sha_512.Sum(nil))
	assert.Equal(t, "2f88ecf29ab10ecaaf0a850ff0bf88c0899af1c40dc941fed808ff14b2e6ad556f144159cec7da63921e1141aecedc223e6a38d1d479a05af6af3f902e8ed197", passwordHash)
}
