package main

import (
	"fmt"
	"github.com/jakubd/zeekparse"
	"strings"
)

// http-week.go - show the last week of non-local, non-reverse DNS resolutions and their replies exclude all domains
// on a whitelist.

func main() {

	// lets look at last 7 days
	for _, thisDay := range zeekparse.LastXDays(7) {

		// pull the DNS for the given day
		thisDaysDNS, err := zeekparse.GetAllDnsForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// we are only interested in lookups against our main DNS resolver
		stubResolverIp := "192.168.1.1"

		// sample whitelist of commonly accessed domains
		whiteListDomains := []string{
			// big g related
			"gstatic.com",
			"googleapis.com",
			"google.com",
			"googleusercontent.com",
			"gvt1.com",
			"google.ca",
			// git stuff
			"github.com",
			"githubusercontent.com",
			"gitcdn.xyz",
			"githubassets.com",
			"gitlab.com",
			// browser stuff
			"userstyles.org",
			"greasyfork.org",
			"eff.org",
			"easylist.to",
			"globalsign.com",
			// dev stuff
			"jetbrains.com",
			"maxmind.com",
			"vsassets.io",
			"visualstudio.com",
			"npmjs.org",
			"stackoverflow.com",
			"golang.com",
			"golang.org",
			"intellij.net.home",
			"intellij.net",
			// linux os stuff
			"met.no",
			"snapcraft.io",
			"graylog.com",
			"bitwarden.com",
			"bgp.he.net",
			"censys.io",
			"influxdata.com",
			"virtualbox.org",
		}

		// iterate all the days dns lookups
		for _, thisLookup := range thisDaysDNS {
			// if the responding host is the stub resolver ip
			if thisLookup.IdRespH == stubResolverIp &&
				// and the query is not blank
				len(thisLookup.Query) > 1 &&
				// and it is not a reverse DNS lookup
				!thisLookup.IsRDNSLookup() {

				// check against the white list
				whiteListHit := false
				for _, thisWhiteListDomain := range whiteListDomains {
					if strings.HasSuffix(thisLookup.Query, thisWhiteListDomain) {
						whiteListHit = true
					}
				}

				if strings.HasSuffix(thisLookup.Query, ".arpa") {
					whiteListHit = true
				}

				// and print if there was no hit.
				if !whiteListHit {
					fmt.Printf("[%s] Client [%s:%d] looked up [%s] and got answer: %s\n", thisLookup.TS.String(),
						thisLookup.IdOrigH, thisLookup.IdOrigP, thisLookup.Query, thisLookup.Answers)
				}

			}
		}
	}
}
