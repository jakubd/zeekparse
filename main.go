package main

import (
	log "github.com/sirupsen/logrus"
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
	log.Info("started main func")

	log.Info("ended main func")
}
