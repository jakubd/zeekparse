package main

import (
	"fmt"
	zeekparse "github.com/jakubd/go-zeek-logparse"
	log "github.com/sirupsen/logrus"
	"os"
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

	for _, thisDate := range zeekparse.LastXMonths(3) {
		allConn, err := zeekparse.GetAllConnForDay(thisDate)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		for _, thisRes := range allConn {
			if strings.HasPrefix(thisRes.IdOrigH, "192.168.1.") &&
				!strings.HasPrefix(thisRes.IdRespH, "192.168.1.") &&
				!zeekparse.IsMulticastOrBroadcastAddress(thisRes.IdRespH) &&
				thisRes.Proto != zeekparse.NONE {
				if thisRes.OrigBytes > thisRes.RespBytes {
					fmt.Printf("{%s} client [%s:%d] uploaded %d bytes to [%s:%d]\n", thisRes.TS.String(), thisRes.IdOrigH, thisRes.IdOrigP,
						thisRes.OrigBytes, thisRes.IdRespH, thisRes.IdRespP)
				}
			}
		}
	}

	log.Info("ended main func")
}
