package main

import (
	"context"
	"encoding/json"
	"fmt"
	alidns "github.com/alibabacloud-go/alidns-20150109/client"
	aliopenapi "github.com/alibabacloud-go/darabonba-openapi/client"
	teaUtil "github.com/alibabacloud-go/tea-utils/service"
	"os"
	"strings"

	"github.com/pkg/errors"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&aliDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type aliDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client         *kubernetes.Clientset
	dnsClient      *alidns.Client
	runtimeOptions *teaUtil.RuntimeOptions
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type aliDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	AccessToken cmmetav1.SecretKeySelector `json:"accessTokenSecretRef"`
	SecretToken cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	Regionid    string                     `json:"regionId"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *aliDNSProviderSolver) Name() string {
	return "alidns-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *aliDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	// TODO: do something more useful with the decoded configuration
	fmt.Printf("Decoded configuration: %v\n", cfg)

	accessToken, err := c.loadSecretData(cfg.AccessToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}
	secretKey, err := c.loadSecretData(cfg.SecretToken, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	clientConfig := new(aliopenapi.Config)
	clientConfig.SetAccessKeyId(string(accessToken)).
		SetAccessKeySecret(string(secretKey)).
		SetRegionId(cfg.Regionid).
		SetConnectTimeout(5000).
		SetReadTimeout(10000)

	client, err := alidns.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("alicloud: error with create client: %v", err)
	}

	runtimeOptions := new(teaUtil.RuntimeOptions).
		SetAutoretry(false).
		SetMaxIdleConns(3).
		SetReadTimeout(5000).
		SetConnectTimeout(10000)

	c.dnsClient = client
	c.runtimeOptions = runtimeOptions

	zoneName, err := c.getHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: error getting hosted zones: %v", err)
	}

	recordAttributes := c.newTxtRecord(zoneName, ch.ResolvedFQDN, ch.Key)

	_, err = c.dnsClient.AddDomainRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("alicloud: error adding domain record: %v", err)
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *aliDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	records, err := c.findTxtRecords(ch.ResolvedZone, ch.ResolvedFQDN)
	if err != nil {
		return fmt.Errorf("alicloud: error finding txt records: %v", err)
	}

	_, err = c.getHostedZone(ch.ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: %v", err)
	}

	for _, rec := range records {
		if ch.Key == *rec.Value {
			request := alidns.DeleteDomainRecordRequest{}
			request.RecordId = rec.RecordId
			_, err = c.dnsClient.DeleteDomainRecord(&request)
			if err != nil {
				return fmt.Errorf("alicloud: error deleting domain record: %v", err)
			}
		}
	}
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *aliDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (aliDNSProviderConfig, error) {
	cfg := aliDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *aliDNSProviderSolver) getHostedZone(resolvedZone string) (string, error) {
	request := alidns.DescribeDomainsRequest{}

	var domains []string
	var startPage int64
	startPage = 1

	keyword := util.UnFqdn(resolvedZone)

	for {
		request.KeyWord = &keyword
		request.PageNumber = &startPage

		response, err := c.dnsClient.DescribeDomains(&request)
		if err != nil {
			return "", fmt.Errorf("alicloud: error describing domains: %v", err)
		}

		if response.Body == nil {
			return "", fmt.Errorf("alicloud: error describing domains: no response body")
		}

		for _, domain := range response.Body.Domains.Domain {
			domains = append(domains, *domain.DomainName)
		}

		pageSize := *response.Body.PageSize
		pageNumber := *response.Body.PageNumber

		if pageSize*pageNumber >= *response.Body.TotalCount {
			break
		}

		startPage++
	}

	var hostedZone string
	for _, zone := range domains {
		if zone == util.UnFqdn(resolvedZone) {
			hostedZone = zone
		}
	}

	if hostedZone == "" {
		return "", fmt.Errorf("zone %s not found in AliDNS", resolvedZone)
	}
	return hostedZone, nil
}

func (c *aliDNSProviderSolver) newTxtRecord(zone, fqdn, value string) *alidns.AddDomainRecordRequest {
	request := alidns.AddDomainRecordRequest{}

	recordType := "TXT"
	recordName := c.extractRecordName(fqdn, zone)

	request.Type = &recordType
	request.DomainName = &zone
	request.RR = &recordName
	request.Value = &value

	return &request
}

func (c *aliDNSProviderSolver) findTxtRecords(domain string, fqdn string) ([]alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := alidns.DescribeDomainRecordsRequest{}
	request.DomainName = &zoneName
	var pageSize int64
	pageSize = 500

	request.PageSize = &pageSize

	var records []alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord

	result, err := c.dnsClient.DescribeDomainRecords(&request)
	if err != nil {
		return records, fmt.Errorf("alicloud: error describing domain records: %v", err)
	}

	recordName := c.extractRecordName(fqdn, zoneName)
	for _, record := range result.Body.DomainRecords.Record {
		if *record.RR == recordName {
			records = append(records, *record)
		}
	}
	return records, nil
}

func (c *aliDNSProviderSolver) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.LastIndex(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}

func (c *aliDNSProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load secret %q", ns+"/"+selector.Name)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, errors.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}
