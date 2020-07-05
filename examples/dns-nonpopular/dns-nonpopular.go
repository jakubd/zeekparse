package main

import (
	"encoding/csv"
	"fmt"
	"github.com/jakubd/zeekparse"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
)

func main() {
	majFilename := getMajesticFilePath()

	if _, err := os.Stat(majFilename); os.IsNotExist(err) {
		err := downloadMajestic()
		if  err != nil {
			panic("download of majestic failed: %s")
		}
	}

	domainList, err := majToMem()
	if err != nil {
		panic("failed copying domain list to memory")
	}

	// we are only interested in lookups against our main DNS resolver
	stubResolverIp := "192.168.1.1"

	for _, thisDate := range zeekparse.LastXMonths(3) {
		fmt.Println(thisDate)
		DNSLookupsForDay, dnsErr := zeekparse.GetAllDnsForDay(thisDate)
		if dnsErr != nil {
			panic("can't read zeek logs in")
		}

		for _, thisLookup := range DNSLookupsForDay {
			if thisLookup.IdRespH == stubResolverIp &&
				// and the query is not blank
				len(thisLookup.Query) > 1 &&
				// and it is not a reverse DNS lookup
				!thisLookup.IsRDNSLookup() {

				inWhiteList := false
				for _, thisDomain := range domainList {
					if strings.HasSuffix(thisLookup.Query, thisDomain) {
						inWhiteList = true
					}
				}

				if !inWhiteList {
					fmt.Printf("[%s] Client [%s:%d] looked up [%s] and got answer: %s\n", thisLookup.TS.String(),
						thisLookup.IdOrigH, thisLookup.IdOrigP, thisLookup.Query, thisLookup.Answers)
				}

			}
		}
	}
}

// load majestic domain list to memory all at once
func majToMem() (domainList []string, err error) {
	f, openErr := os.Open(getMajesticFilePath())
	if openErr != nil {
		err = openErr
		return
	}
	defer f.Close()

	rdr := csv.NewReader(f)
	rdr.Read()
	for {
		record, readErr := rdr.Read()
		if readErr == io.EOF {
			break
		} else if readErr != nil {
			err = readErr
			return
		}
		domainList = append(domainList, record[2])
	}
	return
}

// download the majestic million csv
func downloadMajestic() error{
	url := "http://downloads.majestic.com/majestic_million.csv"
	majFilename := getMajesticFilePath()
	fmt.Printf("downloading majestic million list from %s to dir: %s\n", url, majFilename)
	err := DownloadFile(majFilename, url)
	return err
}

// get the path of where the majestic csv should live
func getMajesticFilePath() string{
	cwd, _ := os.Getwd()
	return path.Join(cwd, "examples", "dns-nonpopular", "input", "million.csv")
}

// download the url to the filepath
func DownloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}