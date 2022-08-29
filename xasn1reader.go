package asn1x

type ASN1PEMReader struct {
    bytes []byte
    pos int
}
func (asn1_file *ASN1PEMReader) FastForward(pos int) {
    asn1_file.pos = pos
}
func (asn1_file *ASN1PEMReader) NextByte() byte {
    if asn1_file.pos < len(asn1_file.bytes) {
        next := asn1_file.bytes[asn1_file.pos]
        asn1_file.pos++
        return next
    }
    return 0
}
func (asn1_file *ASN1PEMReader) ReadNodeLength() int {
    buf:= int(asn1_file.NextByte())
    l := buf & 0x7F;
    if l == buf {
        return l
    }
    if l==1 || l==2 || l==3 {
        xbyte:=0
        for i:=0; i<l; i++ {
            buf = int(asn1_file.NextByte())
            xbyte = (xbyte << 8) | buf
        }
        return xbyte
    }
    return 0
}
func (asn1_file *ASN1PEMReader) ReadRootNode() ASN1Node {
    return asn1_file.ReadNextNode(0)
}
func (asn1_file *ASN1PEMReader) ReadNextNode(depth int) ASN1Node {
    startpos:= asn1_file.pos
    tag:= int(asn1_file.NextByte())
    clength := int(asn1_file.ReadNodeLength())
    end_pos := asn1_file.pos + clength
    hlength := asn1_file.pos - startpos
    cstart := asn1_file.pos    

    node := ASN1Node{tag:tag, hlength:hlength, cstart:cstart, clength:clength}
    if node.HasChildren() {
        if tag==0x03 { // skip BitString unused bits, must be in [0, 7]
            asn1_file.NextByte()
        }
        if clength<=0 && (tag & 0x21)>0 { // indefinite length
            //fmt.Println("#indefinite length") //maybe we can work on this later
            return node
        }
        if clength>0 {
            next_pos := asn1_file.pos
            for next_pos < end_pos{
                child := asn1_file.ReadNextNode(depth+1)
                node.AddChild(child)
                next_pos = asn1_file.pos
            }
        }
    } else {
        node.content = asn1_file.bytes[cstart:cstart+clength]
    }
    asn1_file.FastForward(end_pos)
    return node
}
