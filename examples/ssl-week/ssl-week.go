package main

import (
	"github.com/jakubd/zeekparse"
	"strings"
)

// ssl-week.go - show the last week SSL activity on your machine.

func main() {

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

	// lets look at last 12 days
	for _, thisDay := range zeekparse.LastXDays(12) {

		// pull the SSL data for the given day
		thisDaySSL, err := zeekparse.GetAllSSLForDay(thisDay)
		if err != nil {
			panic(err)
		}

		// iterate all the days ssl requests
		for _, thisLookup := range thisDaySSL {
			var whiteListHit = false
			for _, thisDomain := range whiteListDomains {
				if strings.HasSuffix(thisLookup.ServerName, thisDomain) {
					whiteListHit = true
				}
			}
			if !whiteListHit{
				thisLookup.ShortPrint()
			}
		}
	}
}
