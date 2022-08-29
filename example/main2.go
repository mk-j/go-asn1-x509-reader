package main

import (
    "io/ioutil"
    "github.com/mk-j/go-asn1-x509-parser"
)
//----------------------------------------------------------------------

func main() {    
     

    allbytes, err := ioutil.ReadFile("../certs/cert-ct.pem")
    if (err!=nil) {
        fmt.Println(err)
    }
    rawbin := asn1x.PEMToDER(allbytes)
    reader := asn1x.ASN1PEMReader{ bytes:rawbin, pos:0}
    root:= reader.ReadRootNode()  
    root.OutputAll(0)

}

