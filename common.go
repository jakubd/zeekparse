package zeekparse

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// unixStrToTime will convert timestamps from unix format to a time.time
func unixStrToTime(givenUnixStr string) (resultTime time.Time, err error) {
	var splitUnixTime []string
	splitUnixTime = strings.Split(givenUnixStr, ".")
	if len(splitUnixTime) != 2 {
		err = errors.New("incorrect input unixtime value")
		return
	}

	var intSec, intNSec int64
	intSec, err = strconv.ParseInt(splitUnixTime[0], 10, 64)
	if err != nil {
		return
	}

	intNSec, err = strconv.ParseInt(splitUnixTime[1], 10, 64)
	if err != nil {
		return
	}
	resultTime = time.Unix(intSec, intNSec)
	return
}

// Proto is an enum of tcp protocol, either TCP or UDP
type Proto string

const (
	TCP Proto = "TCP"
	UDP Proto = "UDP"
)

// ZeekNilValue is how null values are expressed in zeek logs, default is "-"
const ZeekNilValue = "-"
