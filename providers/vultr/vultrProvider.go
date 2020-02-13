package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns/dnsutil"
	"github.com/vultr/govultr"

	"github.com/StackExchange/dnscontrol/v2/models"
	"github.com/StackExchange/dnscontrol/v2/providers"
	"github.com/StackExchange/dnscontrol/v2/providers/diff"
)

var features = providers.DocumentationNotes{
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocOfficiallySupported: providers.Cannot(),
}
func init() {
	providers.RegisterDomainServiceProviderType("VULTR", NewProvider, features)
}
type Provider struct {
	client *govultr.Client
	token  string
}
var defaultNS = []string{
	"ns1.vultr.com",
	"ns2.vultr.com",
}
func NewProvider(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	token := m["token"]
	if token == "" {
		return nil, fmt.Errorf("Vultr API token is required")
	}

	client := govultr.NewClient(nil, token)
	client.SetUserAgent("dnscontrol")

	_, err := client.Account.GetInfo(context.Background())
	return &Provider{client, token}, err
}
func (api *Provider) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()

	records, err := api.client.DNSRecord.List(context.Background(), dc.Name)
	if err != nil {
		return nil, err
	}

	curRecords := make([]*models.RecordConfig, len(records))
	for i := range records {
		r, err := toRecordConfig(dc, &records[i])
		if err != nil {
			return nil, err
		}
		curRecords[i] = r
	}

	models.PostProcessRecords(curRecords)

	differ := diff.New(dc)
	_, create, delete, modify := differ.IncrementalDiff(curRecords)

	var corrections []*models.Correction

	for _, mod := range delete {
		id := mod.Existing.Original.(*govultr.DNSRecord).RecordID
		corrections = append(corrections, &models.Correction{
			Msg: fmt.Sprintf("%s; Vultr RecordID: %v", mod.String(), id),
			F: func() error {
				return api.client.DNSRecord.Delete(context.Background(), dc.Name, strconv.Itoa(id))
			},
		})
	}

	for _, mod := range create {
		r := toVultrRecord(dc, mod.Desired, 0)
		corrections = append(corrections, &models.Correction{
			Msg: mod.String(),
			F: func() error {
				return api.client.DNSRecord.Create(context.Background(), dc.Name, r.Type, r.Name, r.Data, r.TTL, r.Priority)
			},
		})
	}

	for _, mod := range modify {
		r := toVultrRecord(dc, mod.Desired, mod.Existing.Original.(*govultr.DNSRecord).RecordID)
		corrections = append(corrections, &models.Correction{
			Msg: fmt.Sprintf("%s; Vultr RecordID: %v", mod.String(), r.RecordID),
			F: func() error {
				return api.client.DNSRecord.Update(context.Background(), dc.Name, r)
			},
		})
	}

	return corrections, nil
}
func (api *Provider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return models.StringsToNameservers(defaultNS), nil
}
func (api *Provider) EnsureDomainExists(domain string) error {
	if ok, err := api.isDomainInAccount(domain); err != nil {
		return err
	}
	else return nil
	return api.client.DNSDomain.Create(context.Background(), domain, "0.0.0.0")
}
func (api *Provider) isDomainInAccount(domain string) (bool, error) {
	domains, err := api.client.DNSDomain.List(context.Background())
	if err != nil {
		return false, err
	}
	for _, d := range domains {
		if d.Domain == domain {
			return true, nil
		}
	}
	return false, nil
}
func toRecordConfig(dc *models.DomainConfig, r *govultr.DNSRecord) (*models.RecordConfig, error) {
	origin, data := dc.Name, r.Data
	rc := &models.RecordConfig{
		TTL:      uint32(r.TTL),
		Original: r,
	}
	rc.SetLabel(r.Name, dc.Name)

	switch rtype := r.Type; rtype {
	case "CNAME", "NS":
		rc.Type = r.Type
		if !strings.HasSuffix(data, ".") {
			data = data + "."
		}
		return rc, rc.SetTarget(dnsutil.AddOrigin(data, origin))
	case "CAA":
		return rc, rc.SetTargetCAAString(data)
	case "MX":
		if !strings.HasSuffix(data, ".") {
			data = data + "."
		}
		return rc, rc.SetTargetMX(uint16(r.Priority), data)
	case "SRV":
		return rc, rc.SetTargetSRVPriorityString(uint16(r.Priority), data)
	case "TXT":
		if !strings.HasPrefix(data, `"`) || !strings.HasSuffix(data, `"`) {
			return nil, errors.New("Unexpected lack of quotes in TXT record from Vultr")
		}
		return rc, rc.SetTargetTXT(data[1 : len(data)-1])
	default:
		return rc, rc.PopulateFromString(rtype, r.Data, origin)
	}
}
func toVultrRecord(dc *models.DomainConfig, rc *models.RecordConfig, vultrID int) *govultr.DNSRecord {
	name := rc.GetLabel()
	if name == "@" {
		name = ""
	}

	data := rc.GetTargetField()

	if strings.HasSuffix(data, ".") {
		data = data[:len(data)-1]
	}
	if rc.Type == "TXT" {
		data = fmt.Sprintf(`"%s"`, data)
	}

	priority := 0

	if rc.Type == "MX" {
		priority = int(rc.MxPreference)
	}
	if rc.Type == "SRV" {
		priority = int(rc.SrvPriority)
	}

	r := &govultr.DNSRecord{
		RecordID: vultrID,
		Type:     rc.Type,
		Name:     name,
		Data:     data,
		TTL:      int(rc.TTL),
		Priority: priority,
	}
	switch rtype := rc.Type; rtype {
	case "SRV":
		r.Data = fmt.Sprintf("%v %v %s", rc.SrvWeight, rc.SrvPort, rc.GetTargetField())
	case "CAA":
		r.Data = fmt.Sprintf(`%v %s "%s"`, rc.CaaFlag, rc.CaaTag, rc.GetTargetField())
	case "SSHFP":
		r.Data = fmt.Sprintf("%d %d %s", rc.SshfpAlgorithm, rc.SshfpFingerprint, rc.GetTargetField())
	default:
	}

	return r
}
