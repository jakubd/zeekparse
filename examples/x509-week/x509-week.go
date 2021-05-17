package main

import (
	"github.com/jakubd/zeekparse"
)

func main() {

	// lets look at last 12 days
	for _, thisDay := range zeekparse.LastXDays(12) {

		// pull the SSL data for the given day
		thisDayCerts, err := zeekparse.GetAllX509ForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// iterate all the days x509 certs
		for _, thisCert := range thisDayCerts {
			thisCert.Print()
		}
	}
}
