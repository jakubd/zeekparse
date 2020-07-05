package zeekparse

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUnixStrToTime(t *testing.T) {
	timestr := "1592266854.705260"
	result, err := UnixStrToTime(timestr)
	assert.NoError(t, err)
	assert.Equal(t, result.Year(), 2020)
	assert.Equal(t, result.Month(), time.Month(6))
	assert.Equal(t, result.Minute(), 20)
	assert.Equal(t, result.Second(), 54)

	failTimeStr := "hello"
	result, err = UnixStrToTime(failTimeStr)
	assert.Error(t, err)

	failTimeStr = "1592266854.hello"
	result, err = UnixStrToTime(failTimeStr)
	assert.Error(t, err)

	failTimeStr = "hello.705260"
	result, err = UnixStrToTime(failTimeStr)
	assert.Error(t, err)
}
