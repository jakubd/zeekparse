package zeekparse

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
)

func parseZeekLog(givenFilename string) (err error) {
	fmt.Println(givenFilename)
	scanner, fHnd, gzipReader, fileSetupErr := setUpFileParse(givenFilename)

	if fHnd != nil {
		defer fHnd.Close()
	}
	if gzipReader != nil {
		defer gzipReader.Close()
	}

	if fileSetupErr != nil {
		err = fileSetupErr
		return
	}

	headerInfo, headerParseErr := parseZeekLogHeader(givenFilename)
	if headerParseErr != nil {
		err = headerParseErr
		return
	}
	log.Debug(headerInfo)

	for scanner.Scan() {
		thisLine := scanner.Text()
		if !strings.HasPrefix(thisLine, "#") {
			log.Debug(thisLine)
		}
	}

	return
}
