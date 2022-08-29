package main

import (
    "fmt"
    "strings"
    "github.com/mk-j/go-asn1-x509-parser"
)
//----------------------------------------------------------------------

func main() {    
     
    r := asn1x.XCert{}
    r.LoadPEM("../certs/cert-ct.pem")
    
    fmt.Printf("cert.version: [%d]\n", r.getVersion())
    fmt.Printf("cert.serialNumber: [%s]\n", r.getSerialNumber())
    fmt.Printf("cert.signatureType: [%s]\n", r.getSignatureType())
    for k,v :=range(r.getIssuer()) {        
        for _,vv:=range(v) {
            fmt.Printf("issuer.%s: [%s]\n", k, vv ) 
        }
        //fmt.Printf("issuer.%s: [%s]\n", k, strings.Join(v,"][") ) 
    }
    validityDates:= r.getValidDates()
    fmt.Printf("validity.issuance: [%s]\n", validityDates[0])
    fmt.Printf("validity.expiry: [%s]\n", validityDates[1])

    for k,v :=range(r.getSubject()) {
        for _,vv:=range(v) {
            fmt.Printf("subject.%s: [%s]\n", k, vv ) 
        }
        //fmt.Printf("subject.%s: [%s]\n", k, strings.Join(v,"][") ) 
    }
    for k,v :=range(r.getKeyInfo()) {
        fmt.Printf("keyInfo.%s: [%s]\n", k, v ) 
    }
    extensions,criticals:= r.getExtensionInfo()
    for k,v :=range(extensions) {
        fmt.Printf("extensionInfo.%s: [%s]\n", k, v ) 
    }
    fmt.Printf("extensionInfo.critical: %s\n", strings.Join(criticals, ","))

}

