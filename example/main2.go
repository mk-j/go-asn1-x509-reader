package main

import (
    "fmt"
    "io/ioutil"
    "github.com/mk-j/go-asn1-x509-reader"
)

func main() {

    allbytes, err := ioutil.ReadFile("../certs/cert-ct.pem")
    if (err!=nil) {
        fmt.Println(err)
    }
    rawbin := asn1x.PEMToDER(allbytes)
    reader := asn1x.ASN1PEMReader{}
    reader.Init(rawbin)
    root:= reader.ReadRootNode()
    root.OutputAll(0)
}

