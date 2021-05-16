package main

import (
	"github.com/jakubd/zeekparse"
	"strings"
)

// http-week.go - show the last week of non-local, non-reverse DNS resolutions and their replies exclude all domains
// on a whitelist.

func main() {

	localSubnet := "192.168.1."

	// lets look at last 12 days
	for _, thisDay := range zeekparse.LastXDays(12) {

		// pull the HTTP for the given day
		thisDayHttp, err := zeekparse.GetAllHttpForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// iterate all the days http requests
		for _, thisLookup := range thisDayHttp {
			if !strings.HasPrefix(thisLookup.IdRespH, localSubnet) {
				thisLookup.ShortPrint()
			}
		}
	}
}
