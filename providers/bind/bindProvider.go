package bind

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/miekg/dns"

	"github.com/StackExchange/dnscontrol/v2/models"
	"github.com/StackExchange/dnscontrol/v2/providers"
	"github.com/StackExchange/dnscontrol/v2/providers/diff"
)

var features = providers.DocumentationNotes{
	providers.CanUseCAA:              providers.Can(),
	providers.CanUsePTR:              providers.Can(),
	providers.CanUseNAPTR:            providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseTLSA:             providers.Can(),
	providers.CanUseTXTMulti:         providers.Can(),
	providers.CantUseNOPURGE:         providers.Cannot(),
	providers.DocCreateDomains:       providers.Can("Driver just maintains list of zone files. It should automatically add missing ones."),
	providers.DocDualHost:            providers.Can(),
	providers.DocOfficiallySupported: providers.Can(),
}

func initBind(config map[string]string, providermeta json.RawMessage) (providers.DNSServiceProvider, error) {
	api := &Bind{
		directory: config["directory"],
	}
	if api.directory == "" {
		api.directory = "zones"
	}
	if len(providermeta) != 0 {
		err := json.Unmarshal(providermeta, api)
		if err != nil {
			return nil, err
		}
	}
	api.nameservers = models.StringsToNameservers(api.DefaultNS)
	return api, nil
}

func init() {
	providers.RegisterDomainServiceProviderType("BIND", initBind, features)
}

type SoaInfo struct {
	Ns      string `json:"master"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minttl  uint32 `json:"minttl"`
}

func (s SoaInfo) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", s.Ns, s.Mbox, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minttl)
}

type Bind struct {
	DefaultNS   []string `json:"default_ns"`
	DefaultSoa  SoaInfo  `json:"default_soa"`
	nameservers []*models.Nameserver
	directory   string
}

func rrToRecord(rr dns.RR, origin string, replaceSerial uint32) (models.RecordConfig, uint32) {
	var oldSerial, newSerial uint32
	header := rr.Header()
	rc := models.RecordConfig{
		Type: dns.TypeToString[header.Rrtype],
		TTL:  header.Ttl,
	}
	rc.SetLabelFromFQDN(strings.TrimSuffix(header.Name, "."), origin)
	switch v := rr.(type) {
	case *dns.A:
		panicInvalid(rc.SetTarget(v.A.String()))
	case *dns.AAAA:
		panicInvalid(rc.SetTarget(v.AAAA.String()))
	case *dns.CAA:
		panicInvalid(rc.SetTargetCAA(v.Flag, v.Tag, v.Value))
	case *dns.CNAME:
		panicInvalid(rc.SetTarget(v.Target))
	case *dns.MX:
		panicInvalid(rc.SetTargetMX(v.Preference, v.Mx))
	case *dns.NS:
		panicInvalid(rc.SetTarget(v.Ns))
	case *dns.PTR:
		panicInvalid(rc.SetTarget(v.Ptr))
	case *dns.NAPTR:
		panicInvalid(rc.SetTargetNAPTR(v.Order, v.Preference, v.Flags, v.Service, v.Regexp, v.Replacement))
	case *dns.SOA:
		oldSerial = v.Serial
		if oldSerial == 0 {
			oldSerial = 1
		}
		newSerial = v.Serial
		if rc.GetLabel() == "@" && replaceSerial != 0 {
			newSerial = replaceSerial
		}
		panicInvalid(rc.SetTarget(
			fmt.Sprintf("%v %v %v %v %v %v %v",
				v.Ns, v.Mbox, newSerial, v.Refresh, v.Retry, v.Expire, v.Minttl),
		))
	case *dns.SRV:
		panicInvalid(rc.SetTargetSRV(v.Priority, v.Weight, v.Port, v.Target))
	case *dns.SSHFP:
		panicInvalid(rc.SetTargetSSHFP(v.Algorithm, v.Type, v.FingerPrint))
	case *dns.TLSA:
		panicInvalid(rc.SetTargetTLSA(v.Usage, v.Selector, v.MatchingType, v.Certificate))
	case *dns.TXT:
		panicInvalid(rc.SetTargetTXTs(v.Txt))
	default:
		log.Fatalf("rrToRecord: Unimplemented zone record type=%s (%v)\n", rc.Type, rr)
	}
	return rc, oldSerial
}

func panicInvalid(err error) {
	if err != nil {
		panic(fmt.Errorf("unparsable record received from BIND: %w", err))
	}
}

func makeDefaultSOA(info SoaInfo, origin string) *models.RecordConfig {
	soaRec := models.RecordConfig{
		Type: "SOA",
	}
	soaRec.SetLabel("@", origin)
	if len(info.Ns) == 0 {
		info.Ns = "DEFAULT_NOT_SET."
	}
	if len(info.Mbox) == 0 {
		info.Mbox = "DEFAULT_NOT_SET."
	}
	if info.Serial == 0 {
		info.Serial = 1
	}
	if info.Refresh == 0 {
		info.Refresh = 3600
	}
	if info.Retry == 0 {
		info.Retry = 600
	}
	if info.Expire == 0 {
		info.Expire = 604800
	}
	if info.Minttl == 0 {
		info.Minttl = 1440
	}
	soaRec.SetTarget(info.String())

	return &soaRec
}
func (c *Bind) GetNameservers(string) ([]*models.Nameserver, error) {
	return c.nameservers, nil
}
func (c *Bind) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()
	soaRec := makeDefaultSOA(c.DefaultSoa, dc.Name)
	foundRecords := make([]*models.RecordConfig, 0)
	var oldSerial, newSerial uint32

	if _, err := os.Stat(c.directory); os.IsNotExist(err) {
		fmt.Printf("\nWARNING: BIND directory %q does not exist!\n", c.directory)
	}

	zonefile := filepath.Join(c.directory, strings.Replace(strings.ToLower(dc.Name), "/", "_", -1)+".zone")
	foundFH, err := os.Open(zonefile)
	zoneFileFound := err == nil
	if err != nil && !os.IsNotExist(os.ErrNotExist) {
		fmt.Printf("Could not read zonefile: %v\n", err)
	} else {
		for x := range dns.ParseZone(foundFH, dc.Name, zonefile) {
			if x.Error != nil {
				log.Println("Error in zonefile:", x.Error)
			} else {
				rec, serial := rrToRecord(x.RR, dc.Name, oldSerial)
				if serial != 0 && oldSerial != 0 {
					log.Fatalf("Multiple SOA records in zonefile: %v\n", zonefile)
				}
				if serial != 0 {
					oldSerial = serial
					newSerial = generateSerial(oldSerial)
					*soaRec, _ = rrToRecord(x.RR, dc.Name, newSerial)
					rec = *soaRec
				}
				foundRecords = append(foundRecords, &rec)
			}
		}
	}
	if !dc.HasRecordTypeName("SOA", "@") {
		dc.Records = append(dc.Records, soaRec)
	}
	models.PostProcessRecords(foundRecords)

	differ := diff.New(dc)
	_, create, del, mod := differ.IncrementalDiff(foundRecords)

	buf := &bytes.Buffer{}
	changes := false
	for _, i := range create {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	for _, i := range del {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	for _, i := range mod {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	msg := fmt.Sprintf("GENERATE_ZONEFILE: %s\n", dc.Name)
	if !zoneFileFound {
		msg = msg + fmt.Sprintf(" (%d records)\n", len(create))
	}
	msg += buf.String()
	corrections := []*models.Correction{}
	if changes {
		corrections = append(corrections,
			&models.Correction{
				Msg: msg,
				F: func() error {
					fmt.Printf("CREATING ZONEFILE: %v\n", zonefile)
					zf, err := os.Create(zonefile)
					if err != nil {
						log.Fatalf("Could not create zonefile: %v", err)
					}
					zonefilerecords := make([]dns.RR, 0, len(dc.Records))
					for _, r := range dc.Records {
						zonefilerecords = append(zonefilerecords, r.ToRR())
					}
					err = WriteZoneFile(zf, zonefilerecords, dc.Name)

					if err != nil {
						log.Fatalf("WriteZoneFile error: %v\n", err)
					}
					err = zf.Close()
					if err != nil {
						log.Fatalf("Closing: %v", err)
					}
					return nil
				},
			})
	}

	return corrections, nil
}
