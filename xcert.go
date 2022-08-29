package asn1x

import (
    "fmt"
    "io/ioutil"
    "strings"
    "encoding/hex"
    "encoding/binary"
    "regexp"
    "crypto/sha1"
    "strconv"
)
//----------------------------------------------------------------------
type XCert struct {
    root ASN1Node
    pem string
    version int
}

func sha1hash(s string) string {
    h := sha1.New()
    h.Write([]byte(s))
    sha1_hash := hex.EncodeToString(h.Sum(nil))
    return sha1_hash
}

func (r *XCert) LoadPEM(filename string) {
    allbytes, err := ioutil.ReadFile(filename)
    if (err!=nil) {
        fmt.Println(err)
    }
    rawbin := PEMToDER(allbytes)
    reader := ASN1PEMReader{ bytes:rawbin, pos:0 }
    r.root = reader.ReadRootNode()
    //r.root.OutputAll(0)
    r.version = r.getVersion()
}

func (r *XCert) whichChild(which int) *ASN1Node {
    if r.getVersion()==3 {
        path:= fmt.Sprintf("0-%d", which)
        return r.root.ChildPath(path)
    }
    return &r.root
}

func (r *XCert) getVersion() int {
    if r.root.ChildPath("0-0-0")!=nil && r.root.ChildPath("0-0").tag==0xa0 && r.root.ChildPath("0-0-0").tag==0x02 {
        encoded_version,_ := strconv.Atoi(r.root.ChildPath("0-0-0").Content())
        return encoded_version+1
    }
    return 1
}

func (r *XCert) getSerialNumber() string {
    return r.whichChild(1).Content()
}

func (r *XCert) getSignatureType() string {
    node:= r.whichChild(2)
    return getOidName(node.ChildPath("0").Content())
}

func (r *XCert) getIssuer() map[string][]string {
    return r.getSubjectIssuer(3)
}

func (r *XCert) getValidDates() []string {
    output := []string{}
    node := r.whichChild(4)
    if  node.ChildPath("0")!=nil {
        output = append(output, node.ChildPath("0").Content())
    }
    if  node.ChildPath("1")!=nil {
        output = append(output, node.ChildPath("1").Content())
    }
    return output
}

func (r *XCert) getSubject() map[string][]string {
    return r.getSubjectIssuer(5)
}

func (r *XCert) getSubjectIssuer(which int) map[string][]string {
    output:= map[string][]string{}
    node := r.whichChild(which)
    for _,child := range(node.Children()) {
        oid := child.ChildPath("0-0").Content()
        oidName := getOidName(oid)
        value := child.ChildPath("0-1").Content()      
        if _, ok:= output[oidName]; ok {
            output[oidName] = append(output[oidName], value)
        } else {
            output[oidName] = []string{ value }
        }
    }
    return output
}

func (r *XCert) countBits(rawbytes []byte) int {
    piece := binary.BigEndian.Uint64(rawbytes[0:8])
    bits := len(strconv.FormatUint(piece,2))
    return len(rawbytes[8:])*8+bits
}

func (r *XCert) getKeyInfo() map[string]string {
    output := map[string]string{}
    node := r.whichChild(6)
    //node.OutputAll(0)
    keydata:= node.ChildPath("1").RawContent()[1:]
    sha1hash := fmt.Sprintf("%x", sha1.Sum(keydata))
    oid := node.ChildPath("0-0").Content()
    output["keyType"] = getOidName(oid)
    output["subjectKeyIdentifier"]  = sha1hash
    if oid == "1.2.840.113549.1.1.1" {
        output["type"]="rsa"
        rawbin := node.ChildPath("1").RawContent()[1:]
        reader := ASN1PEMReader{ bytes:rawbin, pos:0}
        keynode:= reader.ReadRootNode()
        keysize := r.countBits(keynode.ChildPath("0").RawContent())
        exponent:= keynode.ChildPath("1").Content()
        output["keysize"]= fmt.Sprintf("%d", keysize)
        output["exponent"]= exponent
    } else if oid == "1.2.840.10045.2.1" {
        curve := getOidName(node.ChildPath("0-1").Content())
        r, _ := regexp.Compile("\\d+")
        output["type"]="ec"
        output["algorithmCurve"] = curve
        output["keysize"] = r.FindString(output["algorithmCurve"])
    } else if oid == "1.2.840.10040.4.1" {
        if node.ChildPath("0-1-0")!=nil {            
            keysize := r.countBits(node.ChildPath("0-1-0").RawContent())
            output["keysize"] = fmt.Sprintf("%d", keysize)            
        }
        output["type"]="dsa"
    }
    return output
}

func (r *XCert) getExtensionInfo() (map[string]string, []string) {
    extensions := map[string]string {}
    criticals := []string {}
    if r.version!=3 {
        return extensions, criticals
    }
    node := r.whichChild(7)    
    if node!=nil && node.tag==0xa3 && node.ChildPath("0")!=nil && node.ChildPath("0").tag==0x30 { //seq
        for _,xnode := range(node.ChildPath("0").Children()) {
            if xnode.ChildPath("0")!=nil && xnode.ChildPath("1")!=nil && xnode.ChildPath("0").tag==0x06 {
                oid := xnode.ChildPath("0").Content()                
                oidName := getOidName(oid)
                childCount := len(xnode.Children())
                dataChild := "1"
                if childCount==3 {
                    dataChild = "2"
                    if xnode.ChildPath("1").RawContent()[0]==0xff {
                        criticals = append(criticals, oidName)
                    }
                } 
                rawbin := xnode.ChildPath(dataChild).RawContent()
                reader := ASN1PEMReader{ bytes:rawbin, pos:0}
                dataNode:= reader.ReadRootNode()
                extensions[oidName] = r.extension(oid,&dataNode)
            }
        }
    }
    return extensions, criticals
}

func (rcert *XCert) extension(oid string, dataNode *ASN1Node) string {
    entries:= []string{}
    if oid=="2.5.29.14" { //subjectKeyIdentifier
        ski:= dataNode.Content()
        entries = append(entries, ski)
    } else if oid=="2.5.29.35" && dataNode.ChildPath("0")!=nil { //authorityKeyIdentifier
        aki:= fmt.Sprintf("%x", dataNode.ChildPath("0").RawContent())
        entries = append(entries, aki)
    } else if oid=="2.5.29.19" { //basicConstraints
        entryx := "CA:FALSE"
        for _,node := range(dataNode.Children()) {
            if node.tag==0x01 {
                entryx = "CA:TRUE"
            }
        }
        entries = append(entries, entryx)
        for _,node := range(dataNode.Children()) {
            if node.tag==0x02 {
                pathlen,_:=strconv.ParseInt(node.Content(), 16, 64)
                entries = append(entries, fmt.Sprintf("pathlen:%d", pathlen))
            }
        }
    } else if oid=="2.5.29.32" { //certificatePolicies       
        for _,node := range(dataNode.Children()) {
            if node.ChildPath("0")!=nil && node.ChildPath("0").tag==0x06 { //OID
                pol:=fmt.Sprintf("Policy:%s", node.ChildPath("0").Content())
                entries = append(entries, pol) //POLICY
            }
            if node.ChildPath("1-0-1")!=nil && node.ChildPath("1-0-0").Content()=="1.3.6.1.5.5.7.2.1" {
                cps:=fmt.Sprintf("CPS:%s", node.ChildPath("1-0-1").Content())
                entries = append(entries, cps) //CPS
            }
        }
    } else if oid=="2.5.29.31" { //crlDistributionPoints
        for _,crl_node := range(dataNode.Children()) {
            if crl_node.ChildPath("0-0-0")!=nil {
                url:= string(crl_node.ChildPath("0-0-0").RawContent())
                entries = append(entries, url)
            }
        }
    } else if oid=="2.5.29.37" { //extendedKeyUsage
        for _,child_node := range(dataNode.Children()) {
            if child_node.tag==0x06 {
                entries = append(entries, getOidName(child_node.Content()))
            }
        }
    } else if oid=="1.3.6.1.5.5.7.1.1" { //authorityInfoAccess
        for _,child_node := range(dataNode.Children()) {
            if child_node.ChildPath("1")!=nil {
                oidName := getOidName(child_node.ChildPath("0").Content())
                data:= fmt.Sprintf("%s:%s", oidName, child_node.ChildPath("1").RawContent())
                entries = append(entries, data)
            }
        }
    } else if oid=="2.5.29.15" { //keyUsage
        entries = rcert.keyUsageParser(dataNode.RawContent())
    } else if oid=="2.5.29.17" { //subjectAltName
        for _,san := range(dataNode.Children()) {
            //san.OutputAll(0)
            if san.tag==0x82 || san.tag==0x81 {
                entries = append(entries, string(san.RawContent()) )
            } else if san.tag==0xa0 {
                if san.ChildPath("0")!=nil && getOidName(san.ChildPath("0").Content())=="permanentIdentifier" && san.ChildPath("1-0-0")!=nil {
                    entries = append(entries, fmt.Sprintf("permanentIdentifier:%s", san.ChildPath("1-0-0").Content()) )
                } //ELSE UNKNOWN
            } else if san.tag!=0x87 { //#0x80:otherName, 0x83:x400Address, 0x84:directoryName, 0x85:ediPartyName, 0x86:uniformResourceIdentifier, 0x88:registeredID
                entries = append(entries, string(san.RawContent()) )
            } else if len(san.RawContent())==4 {
                raw:= san.RawContent()
                entries = append(entries, fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3]))
            } else if len(san.RawContent())==16 { //ipv16
                v:= san.RawContent()
                ipv6 := fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", v[0:2], v[2:4], v[4:6], v[6:8], v[8:10], v[10:12], v[12:14], v[14:16])
                entries = append(entries, ipv6)
            }
        }
    } else {
        //fmt.Println(oid)
        //dataNode.OutputAll(0)
    }
    return strings.Join(entries, ";")
}

func (r *XCert) keyUsageParser(raw []byte) []string {
    entries:= []string{}
    keyUsages := []string{"digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"}
    unusedbits := int(raw[0])
    if unusedbits>7 {
        return []string{}
    }
    binstr := fmt.Sprintf("%08b", raw[1]) //len(raw)==2
    if len(raw)==3 {
        binstr = fmt.Sprintf("%08b%08b", raw[1],raw[2])
    } else if len(raw)!=2 {
        return []string{}
    }
    for i:=0; i<len(binstr)-unusedbits; i++ {
        if binstr[i]=='1' {
            entries = append(entries, keyUsages[i])
        }
    }
    return entries;
}

/*
func main() {    
     
    r := XCert{}
    //r.LoadPEM("certs/www-digicert-com.pem")
    r.LoadPEM("certs/cert-date.pem")
    
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
*/
