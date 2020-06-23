package main

import (
	"github.com/jakubd/go-zeek-logparse"
	log "github.com/sirupsen/logrus"
	"strings"
)

func setUpLogger() {
	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)
	log.SetLevel(log.InfoLevel)
}

func main() {
	setUpLogger()
	log.Info("started")
	err := ShowDNSForDay("2020-06-22")
	if err != nil {
		panic("some error")
	}
	log.Info("ended main func")
}

func ShowDNSForDay(givenDateTime string) (err error) {
	allRes, err := zeekparse.ParseDnsRecurse("/usr/local/zeek/logs/" + givenDateTime + "/")
	if err != nil {
		return
	}
	for _, thisResult := range allRes {
		if len(thisResult.Answers) > 0 {
			for _, thisAnswer := range thisResult.Answers {
				if len(thisAnswer) > 0 {
					if thisResult.IdRespH == "192.168.1.1" && !(strings.Contains(thisResult.Query, "in-addr.arpa")) {
						thisResult.ShortPrint()
					} else {
						//thisResult.ShortPrint()
					}
				}
			}
		}
	}
	return
}
