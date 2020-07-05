package zeekparse

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// UnixStrToTime will convert timestamps from unix format to a time.time
func UnixStrToTime(givenUnixStr string) (resultTime time.Time, err error) {
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
	TCP  Proto = "TCP"
	UDP  Proto = "UDP"
	NONE Proto = "None"
)

// DateStrToTime converts a datestring of the format YYYY-MM-DD to a proper time.Time object
func DateStrToTime(givenDateStr string) (t time.Time, err error) {
	layout := "2006-01-02"
	t, err = time.Parse(layout, givenDateStr)
	return
}

// Converts a time.Time object to a date str in the format YYYY-MM-DD
func TimeToDateStr(givenTime time.Time) (t string) {
	return givenTime.Format("2006-01-02")
}

// DateRange returns a slice of strings of the date strings (in format YYYY-MM-DD) between two datestrings
// of the same format.  Useful in range operations.
func DateRange(fromStr, toStr string) (dateStrRange []string) {
	fromTime, _ := DateStrToTime(fromStr)
	toTime, _ := DateStrToTime(toStr)
	for d := fromTime; d.Before(toTime); d = d.AddDate(0, 0, 1) {
		dateStrRange = append(dateStrRange, TimeToDateStr(d))
	}
	return
}

// LastXMonths returns a slice of datestrings (in the format YYYY-MM-DD) from the last X months
// helpful for iterating recent results.
func LastXMonths(x int) (dateStrRange []string) {
	toTime := TimeToDateStr(time.Now())
	fromTime := TimeToDateStr(time.Now().AddDate(0, -3, 0))
	return DateRange(fromTime, toTime)
}

// IsMulticastOrBroadcastAddress will tell if the given string is either a multicast address or a broadcast.
// Useful for excluding/including addresses in your script.
func IsMulticastOrBroadcastAddress(givenAddress string) bool {
	if givenAddress == "255.255.255.255" {
		return true
	}
	ip := net.ParseIP(givenAddress)
	return ip.IsMulticast()
}
