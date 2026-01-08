package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml"
)

func main() {
	data, err := os.ReadFile("/home/leifj/work/siros.org/go-trust/pkg/registry/etsi/testdata/li-tsl.xml")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	doc := etree.NewDocument()
	doc.ReadFromBytes(data)

	// Check what X509Certificate elements we find in the whole document
	allCerts := doc.FindElements(".//X509Certificate")
	fmt.Printf("Found %d X509Certificate elements in full document via .//X509Certificate\n", len(allCerts))

	// Check using full XPath
	allCerts2 := doc.FindElements("//X509Certificate")
	fmt.Printf("Found %d X509Certificate elements via //X509Certificate\n", len(allCerts2))

	sig := doc.FindElement("//Signature")
	if sig == nil {
		fmt.Println("No signature found")
		return
	}

	certs := sig.FindElements(".//X509Certificate")
	fmt.Printf("Found %d X509Certificate elements in signature\n", len(certs))

	for i, cert := range certs {
		text := cert.Text()
		text = strings.TrimSpace(text)
		fmt.Printf("\nCert %d: Raw length=%d\n", i, len(text))

		pemStr := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", text)
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			fmt.Printf("  PEM decode: FAILED\n")
			continue
		}
		fmt.Printf("  PEM decode: OK\n")

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Printf("  x509 parse: FAILED - %v\n", err)
			continue
		}
		fmt.Printf("  x509 parse: OK - Subject=%s\n", parsedCert.Subject)
	}

	fmt.Println("\n--- Now testing with signedxml ---")

	validator, err := signedxml.NewValidator(string(data))
	if err != nil {
		fmt.Printf("Error creating validator: %v\n", err)
		return
	}

	validator.SetReferenceIDAttribute("Id")

	// Access internal xml document
	fmt.Println("\nChecking xml in validator:")

	fmt.Printf("Certificates loaded (before validation): %d\n", len(validator.Certificates))

	refs, err := validator.ValidateReferences()
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
		fmt.Printf("Certificates loaded (after validation): %d\n", len(validator.Certificates))
		for i, cert := range validator.Certificates {
			fmt.Printf("  Cert %d: Subject=%s\n", i, cert.Subject)
		}
		return
	}

	fmt.Printf("Success! Validated %d references\n", len(refs))
	fmt.Printf("Certificates loaded (after validation): %d\n", len(validator.Certificates))
}
