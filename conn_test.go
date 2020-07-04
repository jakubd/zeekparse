package zeekparse

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestNewConnStateObj(t *testing.T) {
	S0 := NewConnStateObj("S0")
	assert.Equal(t, S0.Code, "S0")
	assert.Equal(t, S0.Summary, "Connection attempt seen, no reply.")
	S0.Print()

	s0 := NewConnStateObj("s0")
	assert.Equal(t, s0.Code, "S0")
	assert.Equal(t, s0.Summary, "Connection attempt seen, no reply.")
	s0.Print()

	junk := NewConnStateObj("s0asdfas")
	assert.Equal(t, junk.Code, "s0asdfas")
	assert.Equal(t, junk.Summary, "ERR: unknown code")
	junk.Print()
}

func TestThisLogEntryToConnStruct(t *testing.T) {
	// compressed case
	compressedResults, header, compErr := parseZeekLog("test_input/simple_conn.log.gz")
	for _, thisResult := range compressedResults {
		connRes, connErr := thisLogEntryToConnStruct(thisResult, header)
		assert.NoError(t, connErr)
		assert.True(t, len(connRes.Uid) >= 14 && len(connRes.Uid) <= 19)
		assert.True(t, net.ParseIP(connRes.IdOrigH) != nil && net.ParseIP(connRes.IdRespH) != nil)
		assert.True(t, connRes.IdOrigP > 1 && connRes.IdOrigP < 65539)
	}
	assert.NoError(t, compErr)
}

func TestParseConnLog(t *testing.T) {
	_, err := ParseConnLog("test_input/simple_conn.log.gz")
	assert.NoError(t, err)
}
