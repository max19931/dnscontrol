package bind

import (
	"log"
	"strconv"
	"strings"
	"time"
)

var nowFunc = time.Now

func generateSerial(oldSerial uint32) uint32 {
	original := oldSerial
	oldSerialStr := strconv.FormatUint(uint64(oldSerial), 10)
	var newSerial uint32
	today := nowFunc().UTC()
	todayStr := today.Format("20060102")
	version := uint32(1)
	todayNum, err := strconv.ParseUint(todayStr, 10, 32)
	if err != nil {
		log.Fatalf("new serial won't fit in 32 bits: %v", err)
	}
	draft := uint32(todayNum)*100 + version

	method := "none"
	if oldSerial > draft {
		method = "o>d"
		newSerial = oldSerial + 1
		newSerial = oldSerial + 1
	} else if oldSerial == draft {
		method = "o=d"
		newSerial = draft + 1
	} else if len(oldSerialStr) != 10 {
		method = "len!=10"
		newSerial = draft
	}
	else if strings.HasPrefix(oldSerialStr, todayStr) {
		method = "prefix"
		newSerial = oldSerial + 1
	}
	else {
		method = "default"
		newSerial = draft
	}
	if newSerial == 0 {
		newSerial = 1
	}
	if oldSerial == newSerial {
		return
	}
	if oldSerial > newSerial {
		return
	}
	return newSerial
}
