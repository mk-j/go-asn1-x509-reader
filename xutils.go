package asn1x

import (
    "fmt"
    "strings"
    "encoding/base64"
)

func PEMToDER(allbytes []byte) []byte {
    lines := strings.Split(strings.ReplaceAll(string(allbytes), "\r\n", "\n"), "\n")
    trimmed := make([]string, len(lines))
    for i:=0; i<len(lines); i++ {
        if !strings.HasPrefix(lines[i],"-----") {
            trimmed = append(trimmed, lines[i])
        }
    }   
    rawbin,decode_err:= base64.StdEncoding.DecodeString(strings.Join(trimmed,""))
    if (decode_err!=nil) {
        fmt.Println(decode_err)
    }
    return rawbin
}

func Latin1ToUTF8(iso8859_1_buf []byte) string {
    buf := make([]rune, len(iso8859_1_buf))
    for i, b := range iso8859_1_buf {
        buf[i] = rune(b)
    }
    return string(buf)
}
