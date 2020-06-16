package zeekparse

import (
	"errors"
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
	// log.Debug(headerInfo)

	for scanner.Scan() {
		thisLine := scanner.Text()
		if !strings.HasPrefix(thisLine, "#") {
			thisLineSplit := strings.Split(thisLine, headerInfo.separator)
			if len(thisLineSplit) != len(headerInfo.fieldOrder) {
				err = errors.New("mismatch between line in log and fields in header")
				return
			}

			for idx, fieldName := range headerInfo.fieldOrder {
				log.Debugf("#%d: [%s:%s] %s", idx, fieldName, headerInfo.fieldTypeMap[fieldName], thisLineSplit[idx])
			}
			log.Debug(thisLineSplit)
		}
	}

	return
}
