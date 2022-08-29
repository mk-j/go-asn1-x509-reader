package asn1x

import (
    "fmt"
    "strings"
    "encoding/hex"
    "regexp"
    "strconv"
)
//----------------------------------------------------------------------
type ASN1Node struct {
    tag, hlength, cstart, clength int
    content []byte
    child_nodes []ASN1Node
}
func (r *ASN1Node) ChildPath(path string) *ASN1Node {
    pieces:= strings.Split(path, "-")
    var node *ASN1Node =nil
    if r.HasChildren() && len(path)>0 {
        node = r
    }    
    for _,v := range(pieces) {
        which_child,_ := strconv.Atoi(v)
        if which_child < len(node.child_nodes) {
            node = &node.child_nodes[which_child]
        } else {
            return nil
        }
    }
    return node
}
func (r *ASN1Node) HasChildren() bool {
    if r.tag & 0x20 >0 {
        return true
    }   
    return false
}
func (r *ASN1Node) AddChild(child ASN1Node) {
    r.child_nodes = append(r.child_nodes, child)
}
func (r *ASN1Node) Output(depth int) {
    Lshape := "~";
    tabs := strings.Repeat(" ", depth)
    fmt.Printf("%s[%s]\n", tabs, r.InfoStr())
    if !r.HasChildren() {
        fmt.Printf("%s%s[%s]\n", tabs, Lshape, r.Content())
    }
}

func (r *ASN1Node) Children() []ASN1Node {
    return r.child_nodes
}

//func (r *ASN1Node) Child(which int) *ASN1Node {
//    if which<len(r.child_nodes) {
//        return &r.child_nodes[which]
//    }
//    return nil
//}

func (r *ASN1Node) OutputAll(depth int) {
    r.Output(depth)
    for i:=0; i<len(r.child_nodes); i++ {
        child := r.child_nodes[i]
        child.OutputAll(depth+1)
    }
}
func (r *ASN1Node) InfoStr() string {
    tagHex := fmt.Sprintf("0x%02x", r.tag)
    tagClass := r.tag >> 6
    tagCon := (r.tag >> 5) & 1
    tagNum := r.tag & 0x1F
    tagName := r.NodeName()
    clen := r.clength
    return fmt.Sprintf("tag:%s:{len:%d,class:%d,constructed:%d,number:%d,name:%s}", tagHex,clen,tagClass,tagCon,tagNum,tagName)
}
func (r *ASN1Node) RawContent() []byte {
    return r.content    
}
func (r *ASN1Node) Content() string {
    tagNumber := r.tag & 0x1F
    if tagNumber==0x05 { // NULL
        return ""
    } else  if tagNumber==0x06 { //# OID/OBJECT_IDENTIFIER        
        return r.ContentAsOID() //return ASN1Content.oid(content)
    } else if tagNumber==0x13 || tagNumber==0x14 {
        return Latin1ToUTF8(r.content)
    } else if tagNumber==0x01 || tagNumber==0x02 || tagNumber==0x03 || tagNumber==0x04 {
        return hex.EncodeToString(r.content)
    } else if tagNumber==0x0C || tagNumber==0x12 || tagNumber==0x16 || tagNumber==0x1A || tagNumber==0x1B {
        return string(r.content)   // content.decode('utf-8')
    } else if tagNumber==0x17 || tagNumber==0x18 {
        return r.ContentAsDate() // return ASN1Content.date(content)
    } else if tagNumber==0x1C {
        return "[utf32]" // return content.decode('utf_32be')
    } else if tagNumber==0x1E {
        return "[utf16]" // return content.decode('utf_16be')
    }
    return "[content]"
}
func (r *ASN1Node) NodeName() string {
    nodeNameDict := map[int]string{
        0x00:"EOC"             , 0x09:"Real"           , 0x15:"VideoTexString"  ,
        0x01:"BOOLEAN"         , 0x0A:"Enumerated"     , 0x16:"IA5String"       ,
        0x02:"INTEGER"         , 0x0B:"EmbeddedPDV"    , 0x17:"UTCTime"         ,
        0x03:"BIT_STRING"      , 0x0C:"UTF8String"     , 0x18:"GeneralizedTime" ,
        0x04:"OCTET_STRING"    , 0x10:"SEQUENCE"       , 0x19:"GraphicString"   ,
        0x05:"NULL"            , 0x11:"SET"            , 0x1A:"VisibleString"   ,
        0x06:"OID"             , 0x12:"NumericString"  , 0x1B:"GeneralString"   ,
        0x07:"ObjectDescriptor", 0x13:"PrintableString", 0x1C:"UniversalString" ,
        0x08:"External"        , 0x14:"T61String"      , 0x1E:"BMPString"       ,
    }

    tagClass := r.tag >> 6
    tagNumber := r.tag & 0x1F
    if tagClass==0 { //universal
        if nodeName, exists := nodeNameDict[tagNumber]; exists {
            return nodeName
        }
        return fmt.Sprintf("Universal_%02X", tagNumber)
    } else if tagClass==1 {
        return fmt.Sprintf("Application_%02X", tagNumber)
    } else if tagClass==2 {
        return "CONTEXT_SPECIFIC"
    } else if tagClass==3 {
        return fmt.Sprintf("Private_%02X", tagNumber)
    }
    return "unknown";
}

func (r *ASN1Node) ContentAsOID() string {
    s:= ""
    n:=0
    bits:=0
    for i:=0; i<len(r.content); i++ {
        c := r.content[i]
        v := int(c)
        n = (n << 7 ) | (v & 0x7f)
        bits +=7
        if (v & 0x80)==0 {
            if len(s)==0 {
                s = fmt.Sprintf( "%s%d.%d" , s, int(n/40), n%40 )
            } else if bits<32 {
                s = fmt.Sprintf( "%s.%d" , s, n )
            } else {
                s = fmt.Sprintf( "%s[bigint]", s)
            }
            n=0
            bits=0
        }
    }
    return s
}
func (r *ASN1Node) ContentAsDate() string {
    // YYMMDDhhmmZ (test) (YY below 50, 2049... YY>=50 1951)
    // YYYYMMDDhhmmZ (test)
    d := string(r.content)    
    z,_ := strconv.Atoi(string(d[0]))
    prefix := 19
    if z<5 {
        prefix = 20
    }
    if match, _ := regexp.MatchString("^([0-9]+){12}Z", d); match {
        return fmt.Sprintf("%d%s-%s-%s %s:%s:%s GMT", prefix, d[0:2],d[2:4],d[4:6],d[6:8],d[8:10],d[10:12])
    }
    if match, _ := regexp.MatchString("^([0-9]+){14}Z", d); match {
        return fmt.Sprintf("%s-%s-%s %s:%s:%s GMT", d[0:4],d[4:6],d[6:8],d[8:10],d[10:12],d[12:14])
    }
    if match, _ := regexp.MatchString("^([0-9]+){10}Z", d); match {
        return fmt.Sprintf("%d%s-%s-%s %s:%s GMT", prefix, d[0:2],d[2:4],d[4:6],d[6:8],d[8:10])
    }
    if match, _ := regexp.MatchString("^([0-9]+){12}\\+0000", d); match {
        return fmt.Sprintf("%d%s-%s-%s %s:%s:%s GMT", prefix, d[0:2],d[2:4],d[4:6],d[6:8],d[8:10],d[10:12])
    }
    return "[invalid date]"
}

//----------------------------------------------------------------------


