// Package nameservers provides logic for dynamically finding nameservers for a domain, and configuring NS records for them.
package nameservers

import (
	"fmt"
	"strings"

	"strconv"

	"github.com/StackExchange/dnscontrol/v2/models"
)

// DetermineNameservers will find all nameservers we should use for a domain. It follows the following rules:
// 1. All explicitly defined NAMESERVER records will be used.
// 2. Each DSP declares how many nameservers to use. Default is all. 0 indicates to use none.
func DetermineNameservers(dc *models.DomainConfig) ([]*models.Nameserver, error) {
	// always take explicit
	ns := dc.Nameservers
	for _, dnsProvider := range dc.DNSProviderInstances {
		n := dnsProvider.NumberOfNameservers
		if n == 0 {
			continue
		}
		fmt.Printf("----- Getting nameservers from: %s\n", dnsProvider.Name)
		nss, err := dnsProvider.Driver.GetNameservers(dc.Name)
		if err != nil {
			return nil, err
		}
		take := len(nss)
		if n > 0 && n < take {
			take = n
		}
		for i := 0; i < take; i++ {
			nss[i].Name = strings.TrimRight(nss[i].Name, ".")
			// FIXME(tlim): Rather than correct broken providers, we should print
			// a warning that the provider should be updated to store the FQDN
			// with no trailing dot.  See also providers/namedotcom/nameservers.go
			// Bug https://github.com/StackExchange/dnscontrol/v2/issues/491
			ns = append(ns, nss[i])
		}
	}
	return ns, nil
}

// AddNSRecords creates NS records on a domain corresponding to the nameservers specified.
func AddNSRecords(dc *models.DomainConfig) {
	ttl := uint32(300)
	if ttls, ok := dc.Metadata["ns_ttl"]; ok {
		t, err := strconv.ParseUint(ttls, 10, 32)
		if err != nil {
			fmt.Printf("WARNING: ns_ttl for %s (%s) is not a valid int", dc.Name, ttls)
		} else {
			ttl = uint32(t)
		}
	}
	for _, ns := range dc.Nameservers {
		rc := &models.RecordConfig{
			Type:     "NS",
			Metadata: map[string]string{},
			TTL:      ttl,
		}
		rc.SetLabel("@", dc.Name)
		t := ns.Name
		if !strings.HasSuffix(t, ".") {
			t += "."
		}
		rc.SetTarget(t)

		dc.Records = append(dc.Records, rc)
	}
}
