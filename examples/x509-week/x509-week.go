package main

import (
	"fmt"
	"github.com/jakubd/zeekparse"
)

// Contains tells whether a contains x.
func Contains(a []string, x string) bool {
	for _, n := range a {
		if x == n {
			return true
		}
	}
	return false
}

func main() {
	var seenCerts []string
	// lets look at last 12 days
	for _, thisDay := range zeekparse.LastXDays(12) {

		// pull the SSL data for the given day
		thisDayCerts, err := zeekparse.GetAllX509ForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// iterate all the days x509 certs
		for _, thisCert := range thisDayCerts {
			if !Contains(seenCerts, thisCert.CertSubject) {
				seenCerts = append(seenCerts, thisCert.CertSubject)
			}
		}
	}

	for _, thisCert := range seenCerts {
		fmt.Println(thisCert)
	}
}
