package zeekparse

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConnStateObj(t *testing.T) {
	S0 := NewConnStateObj("S0")
	assert.Equal(t, S0.Code, "S0")
	assert.Equal(t, S0.Summary, "Connection attempt seen, no reply.")

	s0 := NewConnStateObj("s0")
	assert.Equal(t, s0.Code, "S0")
	assert.Equal(t, s0.Summary, "Connection attempt seen, no reply.")

	junk := NewConnStateObj("s0asdfas")
	assert.Equal(t, junk.Code, "S0ASDFAS")
	assert.Equal(t, junk.Summary, "")
}
