package face

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	API_HOST   = "mosapi.meituan.com"
	API_PATH   = "/mcs/v1"
	API        = "https://" + API_HOST + API_PATH
	Action     = "PairVerifyFace"
	TimeFormat = "2006-01-02T15:04:05.000Z0700"

	DefaultSigVersion = "2"
	DefaultSigMethod  = "HmacSHA256"
	DefaultNegRate    = "99.9"
	DefaultFormat     = "json"

	Suc = 200
)

type Compare struct {
	AccessKeyId      string
	AccessKeySecret  string
	Format           string
	SignatureVersion string
	SignatureMethod  string
	NegRate          string
}

type CompareResult struct {
	// 相同的比例
	PairVerifySimilarity float64 `json:"pair_verify_similarity"`
	// 0 表示相同，1表示不同
	PairVerifyResult     int     `json:"pair_verify_result"`
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
		AccessKeySecret:  secret,
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
		"Action", Action,
		"Format", v.Format,
		"SignatureMethod", v.SignatureMethod,
		"SignatureVersion", v.SignatureVersion,
		"Timestamp", time.Now().UTC().Format(TimeFormat),
		"true_negative_rate", v.NegRate,
	}

	var urlValues = make(url.Values)
	var paramEncoded []string
	for i := 0; i < len(paramPairs); i += 2 {
		paramEncoded = append(paramEncoded, paramPairs[i]+"="+url.QueryEscape(paramPairs[i+1]))
		urlValues.Set(paramPairs[i], paramPairs[i+1])
	}

	// 签名
	var h = hmac.New(sha256.New, []byte(v.AccessKeySecret))
	h.Write([]byte(
		strings.Join([]string{
			"POST", API_HOST, API_PATH, strings.Join(paramEncoded, "&"),
		}, "\n"),
	))

	urlValues.Set("Signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	urlValues.Set("first_image_content", base64.StdEncoding.EncodeToString(first))
	urlValues.Set("second_image_content", base64.StdEncoding.EncodeToString(second))

	res, err := http.DefaultClient.PostForm(API, urlValues)
	if res != nil {
		defer res.Body.Close()
		var ret = map[string]struct {
			Code int
			Err  string
			Ret  CompareResult
		}{}
		if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
			return nil, err
		}

		result := ret["PairVerifyFaceResponse"]
		if result.Code != Suc {
			return nil, errors.New(result.Err)
		}

		return &result.Ret, nil
	}

	return nil, err
}
