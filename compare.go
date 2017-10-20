package face

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

var (
	Api       = "https://mosapi.meituan.com/mcs/v1"
	ApiUrl, _ = url.Parse(Api)

	TimeFormat = "2006-01-02T15:04:05.000Z0700"
	RetCodeSuc = 200

	DefaultSigVersion = "2"
	DefaultSigMethod  = "HmacSHA256"
	DefaultNegRate    = "99.9"
	DefaultFormat     = "json"
)

var (
	CompareAction  = "PairVerifyFace"
	CompareSignPre = http.MethodPost + "\n" + ApiUrl.Host + "\n" + ApiUrl.Path + "\n"
)

type Compare struct {
	AccessKeySecret  []byte
	AccessKeyId      string
	Format           string
	SignatureVersion string
	SignatureMethod  string
	NegRate          string
}

type CompareResult struct {
	// 相同的比例
	PairVerifySimilarity float64 `json:"pair_verify_similarity"`
	// 0 表示相同，1表示不同
	PairVerifyResult int `json:"pair_verify_result"`
}

func init() {
	// 设置default client的transport默认使用http1.1
	http.DefaultClient.Transport = &http.Transport{
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
}

func NewCompare(id, secret string) *Compare {
	return &Compare{
		AccessKeyId:      id,
		AccessKeySecret:  []byte(secret),
		SignatureVersion: DefaultSigVersion,
		SignatureMethod:  DefaultSigMethod,
		NegRate:          DefaultNegRate,
		Format:           DefaultFormat,
	}
}

// first second 为两张图片的bytes
func (v *Compare) Do(first, second []byte) (*CompareResult, error) {
	var paramPairs = []string{
		"AWSAccessKeyId", v.AccessKeyId,
		"Action", CompareAction,
		"Format", v.Format,
		"SignatureMethod", v.SignatureMethod,
		"SignatureVersion", v.SignatureVersion,
		"Timestamp", time.Now().UTC().Format(TimeFormat),
		"true_negative_rate", v.NegRate,
	}

	var urlValues = make(url.Values)
	var buf bytes.Buffer
	buf.WriteString(CompareSignPre)
	for i := 0; i < len(paramPairs); i += 2 {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(url.QueryEscape(paramPairs[i]))
		buf.WriteByte('=')
		buf.WriteString(url.QueryEscape(paramPairs[i+1]))
		urlValues.Set(paramPairs[i], paramPairs[i+1])
	}

	// 签名
	var h = hmac.New(sha256.New, v.AccessKeySecret)
	h.Write(buf.Bytes())

	urlValues.Set("Signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	urlValues.Set("first_image_content", base64.StdEncoding.EncodeToString(first))
	urlValues.Set("second_image_content", base64.StdEncoding.EncodeToString(second))

	res, err := http.DefaultClient.PostForm(Api, urlValues)
	if res != nil {
		defer res.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	var ret = map[string]struct {
		Code int
		Err  string
		Ret  CompareResult
	}{}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}

	result := ret["PairVerifyFaceResponse"]
	if result.Code != RetCodeSuc {
		return nil, errors.New(result.Err)
	}

	return &result.Ret, nil
}
