// Independently recover and validate protected aggregate SVM outputs.
package main
import(
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "math"
 "os"
 "path/filepath"
 eth "github.com/ethereum/go-ethereum/crypto"
)
func must(e error){if e!=nil{panic(e)}}
func read(p string)[]byte{b,e:=os.ReadFile(p);must(e);return b}
func open(k,nonce,ct,tag []byte)[]byte{b,e:=aes.NewCipher(k);must(e);g,e:=cipher.NewGCM(b);must(e);p,e:=g.Open(nil,nonce,append(bytes.Clone(ct),tag...),nil);must(e);return p}
func message(k,b []byte,n int,last byte)[]byte{
 if len(b)!=12+n+16{panic("message length")};nonce:=make([]byte,12);nonce[11]=last
 if !bytes.Equal(b[:12],nonce){panic("message nonce")};return open(k,nonce,b[12:12+n],b[12+n:])
}
func main(){
 if len(os.Args)!=3{panic("usage: svmpilotverify REFERENCE_JSON OUTPUT")}
 dir:=os.Args[2];load:=func(s string)[]byte{return read(filepath.Join(dir,s))}
 keys,ida,dc:=load("public-session-keys.bin"),load("ida.msg"),load("dc.msg")
 if len(keys)!=32||len(ida)!=52||len(dc)!=128||bytes.Equal(keys[:16],keys[16:]){panic("layout")}
 for _,b:=range [][]byte{ida,dc}{if binary.LittleEndian.Uint32(b[:4])!=1||binary.LittleEndian.Uint32(b[4:8])!=1{panic("recipient")}}
 key:=message(keys[:16],ida[8:],16,1);kh:=message(keys[16:],dc[8:68],32,1);ch:=message(keys[16:],dc[68:],32,2)
 ct,tag:=load("result.enc"),load("result.tag")
 if len(ct)==0||len(ct)>512||len(tag)!=16{panic("result size")}
 if !bytes.Equal(kh,eth.Keccak256([]byte(hex.EncodeToString(key))))||!bytes.Equal(ch,eth.Keccak256([]byte(hex.EncodeToString(ct)))){panic("key or full ciphertext hash")}
 raw:=open(key,make([]byte,12),ct,tag)
 var got,want map[string]float64;must(json.Unmarshal(raw,&got));must(json.Unmarshal(read(os.Args[1]),&want))
 if len(got)!=4||len(want)!=4{panic("result schema")}
 for _,name:=range []string{"count","support_vectors","training_correct","rho"}{
  a,ok:=got[name];b,bok:=want[name];tol:=0.0;if name=="rho"{tol=1e-7*(1+math.Abs(b))}
  if !ok||!bok||math.IsNaN(a)||math.IsInf(a,0)||math.Abs(a-b)>tol{panic(fmt.Sprintf("reference mismatch %s %.17g %.17g",name,a,b))}
 }
 fmt.Println(string(raw))
}
