package zeekparse

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Proto is an enum of tcp protocol, either TCP or UDP
type Proto string
const (
	TCP  Proto = "TCP"
	UDP  Proto = "UDP"
	NONE Proto = "None"
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

// DateStrToTime converts a datestring of the format YYYY-MM-DD to a proper time.Time object
func DateStrToTime(givenDateStr string) (t time.Time, err error) {
	layout := "2006-01-02"
	t, err = time.Parse(layout, givenDateStr)
	return
}

// TimeToDateStr Converts a time.Time object to a date str in the format YYYY-MM-DD
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
	fromTime := TimeToDateStr(time.Now().AddDate(0, -x, 0))
	return DateRange(fromTime, toTime)
}

// LastXDays returns a slice of datestrings (in the format YYYY-MM-DD) from the last X months
// helpful for iterating recent results.
func LastXDays(x int) (dateStrRange []string) {
	toTime := TimeToDateStr(time.Now())
	fromTime := TimeToDateStr(time.Now().AddDate(0, 0, -x))
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

// StrBlankIfUnset is a convenience function for parsers that will
// return the given value or a blank string if it matches the unset char given.
func StrBlankIfUnset(givenValue string, givenUnset string) string {
	if givenValue == givenUnset {
		return ""
	} else {
		return givenValue
	}
}

// GetZeekDir will return the default zeek dir or what is passed in
func GetZeekDir(givenZeekDir []string) string{
	var zeekDir string
	if len(givenZeekDir) == 0 {
		zeekDir = "/usr/local/zeek/logs/"
	} else {
		zeekDir = givenZeekDir[0]
		if zeekDir[len(zeekDir)-1:] != "/" {
			zeekDir = zeekDir + "/"
		}
	}
	return zeekDir
}

// PathRecurse is used for day recursion type functions.  Pass in a directory and a fragment
// of the filename and it will return a channel of strings that have filenames.
func PathRecurse(givenDirectory string, givenFilenameFragment string) <-chan string {
	var filenames []string

	_ = filepath.Walk(givenDirectory,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.Contains(path, givenFilenameFragment+".") {
				filenames = append(filenames, path)
			}
			return err
		})

	thisChan := make(chan string)
	go func() {
		for _, thisFile := range filenames {
			thisChan <- thisFile
		}
		close(thisChan)
	}()

	return thisChan
}