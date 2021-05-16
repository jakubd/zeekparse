package main

import (
	"github.com/jakubd/zeekparse"
)

// ssl-week.go - show the last week SSL activity on your machine.

func main() {

	// lets look at last 12 days
	for _, thisDay := range zeekparse.LastXDays(12) {

		// pull the SSL data for the given day
		thisDaySSL, err := zeekparse.GetAllSSLForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// iterate all the days ssl requests
		for _, thisLookup := range thisDaySSL {
			thisLookup.ShortPrint()
		}
	}
}
