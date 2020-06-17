[![Actions Status](https://github.com/jakubd/go-zeek-logparse/workflows/Test/badge.svg)](https://github.com/jakubd/go-zeek-logparse/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/jakubd/go-zeek-logparse)](https://goreportcard.com/report/github.com/jakubd/go-zeek-logparse)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

# go-zeek-logparse

A work-in-progress log parser for common zeek text logs.

# Status of WIP

* [X] handles gz compressed and uncompressed files
* [X] Can parse values from headers.
* [X] Can parse log entries into Go structures.
* [ ] Can parse dns.log entries.
* [ ] Can parse conn.log entries.
* [ ] Can parse http.log entries.
* [ ] Can parse ssl.log entries.
* [ ] Can parse ssh.log entries.
* [ ] Can parse dhcp.log entries. 