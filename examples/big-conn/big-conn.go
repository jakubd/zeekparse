package main

import (
	"fmt"
	zeekparse "github.com/jakubd/go-zeek-logparse"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

func setUpLogger() {
	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)
	log.SetLevel(log.InfoLevel)
}

func DateStrToTime(givenDateStr string) (t time.Time, err error) {
	layout := "2006-01-02"
	t, err = time.Parse(layout, givenDateStr)
	return
}

func TimeToDateStr(givenTime time.Time) (t string) {
	return givenTime.Format("2006-01-02")
}

func DateRange(fromStr, toStr string) (dateStrRange []string) {
	fromTime, _ := DateStrToTime(fromStr)
	toTime, _ := DateStrToTime(toStr)
	for d := fromTime; d.Before(toTime); d = d.AddDate(0, 0, 1) {
		dateStrRange = append(dateStrRange, TimeToDateStr(d))
	}
	return
}

func lastXMonths(x int) (dateStrRange []string) {
	toTime := TimeToDateStr(time.Now())
	fromTime := TimeToDateStr(time.Now().AddDate(0, -3, 0))
	return DateRange(fromTime, toTime)
}

func main() {
	setUpLogger()
	log.Info("started")

	for _, thisDate := range lastXMonths(3) {
		allConn, err := getAllConnForDay(thisDate)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		for _, thisRes := range allConn {
			if thisRes.IdOrigH == "192.168.1.139" {
				if thisRes.OrigBytes > thisRes.RespBytes {
					fmt.Printf("{client %s:%d} uploaded %d bytes to %s:%d\n", thisRes.IdOrigH, thisRes.IdOrigP,
						thisRes.OrigBytes, thisRes.IdRespH, thisRes.IdRespP)
				}
			}
		}
	}

	log.Info("ended main func")
}

func getAllConnForDay(givenDay string) (allRes []zeekparse.ConnEntry, err error) {
	allRes, err = zeekparse.ParseConnRecurse("/usr/local/zeek/logs/" + givenDay + "/")
	return
}
