package main

import (
    "fmt"
    "strings"
    "github.com/mk-j/go-asn1-x509-reader"
)

func main() {    
     
    r := asn1x.XCert{}
    r.LoadPEM("../certs/cert-ct.pem")
    
    fmt.Printf("cert.version: [%d]\n", r.GetVersion())
    fmt.Printf("cert.serialNumber: [%s]\n", r.GetSerialNumber())
    fmt.Printf("cert.signatureType: [%s]\n", r.GetSignatureType())
    for k,v :=range(r.GetIssuer()) {
        for _,vv:=range(v) {
            fmt.Printf("issuer.%s: [%s]\n", k, vv ) 
        }
        //fmt.Printf("issuer.%s: [%s]\n", k, strings.Join(v,"][") ) 
    }
    validityDates:= r.GetValidDates()
    fmt.Printf("validity.issuance: [%s]\n", validityDates[0])
    fmt.Printf("validity.expiry: [%s]\n", validityDates[1])

    for k,v :=range(r.GetSubject()) {
        for _,vv:=range(v) {
            fmt.Printf("subject.%s: [%s]\n", k, vv ) 
        }
        //fmt.Printf("subject.%s: [%s]\n", k, strings.Join(v,"][") ) 
    }
    for k,v :=range(r.GetKeyInfo()) {
        fmt.Printf("keyInfo.%s: [%s]\n", k, v ) 
    }
    extensions,criticals:= r.GetExtensionInfo()
    for k,v :=range(extensions) {
        fmt.Printf("extensionInfo.%s: [%s]\n", k, v ) 
    }
    fmt.Printf("extensionInfo.critical: %s\n", strings.Join(criticals, ","))

}

