package aws_rolesanywhere

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/youmark/pkcs8"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	aws4X509RsaSha256 = "AWS4-X509-RSA-SHA256"
	timeFormat        = "20060102T150405Z"
	shortTimeFormat   = "20060102"

	xAmzContentSha256 = "X-Amz-Content-Sha256"
	authorization     = "Authorization"
	host              = "Host"
	emptyStringSHA256 = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")
)

// Signer Interface that all signers will have to implement
// (as a result, they will also implement crypto.Signer)
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Certificate() (certificate *x509.Certificate, err error)
	Close()
}

// CertificateData Container for certificate data returned to the SDK as JSON.
type CertificateData struct {
	// Type for the key contained in the certificate.
	// Passed back to the `sign-string` command
	KeyType string `json:"keyType"`
	// Certificate, as base64-encoded DER; used in the `x-amz-x509`
	// header in the API request.
	CertificateData string `json:"certificateData"`
	// Serial number of the certificate. Used in the credential
	// field of the Authorization header
	SerialNumber string `json:"serialNumber"`
	// Supported signing algorithms based on the KeyType
	Algorithms []string `json:"supportedAlgorithms"`
}

type SignerParams struct {
	OverriddenDate   time.Time
	RegionName       string
	ServiceName      string
	SigningAlgorithm string
}

// Headers that aren't included in calculating the signature
var ignoredHeaderKeys = map[string]bool{
	"Authorization":   true,
	"User-Agent":      true,
	"X-Amzn-Trace-Id": true,
}

// GetFormattedSigningDateTime Obtain the date-time, formatted as specified by SigV4
func (signerParams *SignerParams) GetFormattedSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(timeFormat)
}

// GetFormattedShortSigningDateTime Obtain the short date-time, formatted as specified by SigV4
func (signerParams *SignerParams) GetFormattedShortSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(shortTimeFormat)
}

// GetScope Obtain the scope as part of the SigV4-X509 signature
func (signerParams *SignerParams) GetScope() string {
	var scopeStringBuilder strings.Builder
	scopeStringBuilder.WriteString(signerParams.GetFormattedShortSigningDateTime())
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.RegionName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.ServiceName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString("aws4_request")
	return scopeStringBuilder.String()
}

// Create the canonical query string.
func createCanonicalQueryString(r *http.Request) string {
	rawQuery := strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	return rawQuery
}

const doubleSpace = "  "

// stripExcessSpaces will rewrite the passed in slice's string values to not
// contain muliple side-by-side spaces.
func stripExcessSpaces(vals []string) {
	var j, k, l, m, spaces int
	for i, str := range vals {
		// Trim trailing spaces
		for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
		}

		// Trim leading spaces
		for k = 0; k < j && str[k] == ' '; k++ {
		}
		str = str[k : j+1]

		// Strip multiple spaces.
		j = strings.Index(str, doubleSpace)
		if j < 0 {
			vals[i] = str
			continue
		}

		buf := []byte(str)
		for k, m, l = j, j, len(buf); k < l; k++ {
			if buf[k] == ' ' {
				if spaces == 0 {
					// First space.
					buf[m] = buf[k]
					m++
				}
				spaces++
			} else {
				// End of multiple spaces.
				spaces = 0
				buf[m] = buf[k]
				m++
			}
		}

		vals[i] = string(buf[:m])
	}
}

// Create the canonical header string.
func createCanonicalHeaderString(r *http.Request) (string, string) {
	var headers []string
	signedHeaderVals := make(http.Header)
	for k, v := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if ignoredHeaderKeys[canonicalKey] {
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			signedHeaderVals[lowerCaseKey] = append(signedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		headerValues[i] = k + ":" + strings.Join(signedHeaderVals[k], ",")
	}
	stripExcessSpaces(headerValues)
	return strings.Join(headerValues, "\n"), strings.Join(headers, ";")
}

// Create the canonical request.
func createCanonicalRequest(r *http.Request, contentSha256 string) (string, string) {
	var canonicalRequestStrBuilder strings.Builder
	canonicalHeaderString, signedHeadersString := createCanonicalHeaderString(r)
	canonicalRequestStrBuilder.WriteString("POST")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString("/sessions")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(createCanonicalQueryString(r))
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(canonicalHeaderString)
	canonicalRequestStrBuilder.WriteString("\n\n")
	canonicalRequestStrBuilder.WriteString(signedHeadersString)
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(contentSha256)
	canonicalRequestString := canonicalRequestStrBuilder.String()
	canonicalRequestStringHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	return hex.EncodeToString(canonicalRequestStringHashBytes[:]), signedHeadersString
}

// Find the SHA256 hash of the provided request body as a io.ReadSeeker
func makeSha256Reader(reader io.ReadSeeker) []byte {
	hash := sha256.New()
	start, _ := reader.Seek(0, 1)
	defer reader.Seek(start, 0)

	io.Copy(hash, reader)
	return hash.Sum(nil)
}

// Calculate the hash of the request body
func calculateContentHash(r *http.Request, body io.ReadSeeker) string {
	hash := r.Header.Get(xAmzContentSha256)

	if hash == "" {
		if body == nil {
			hash = emptyStringSHA256
		} else {
			hash = hex.EncodeToString(makeSha256Reader(body))
		}
	}

	return hash
}

// Convert certificate to string, so that it can be present in the HTTP request header
func certificateToString(certificate *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// createStringToSign Create the string to sign.
func createStringToSign(canonicalRequest string, signerParams SignerParams) string {
	var stringToSignStrBuilder strings.Builder
	stringToSignStrBuilder.WriteString(signerParams.SigningAlgorithm)
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetFormattedSigningDateTime())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetScope())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(canonicalRequest)
	stringToSign := stringToSignStrBuilder.String()
	return stringToSign
}

// buildAuthorizationHeader Builds the complete authorization header
func buildAuthorizationHeader(signedHeadersString string, signature string, certificate *x509.Certificate, signerParams SignerParams) string {
	signingCredentials := certificate.SerialNumber.String() + "/" + signerParams.GetScope()
	credential := "Credential=" + signingCredentials
	signerHeaders := "SignedHeaders=" + signedHeadersString
	signatureHeader := "Signature=" + signature

	var authHeaderStringBuilder strings.Builder
	authHeaderStringBuilder.WriteString(signerParams.SigningAlgorithm)
	authHeaderStringBuilder.WriteString(" ")
	authHeaderStringBuilder.WriteString(credential)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signerHeaders)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signatureHeader)
	authHeaderString := authHeaderStringBuilder.String()
	return authHeaderString
}

func encodeDer(der []byte) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(der)
	encoder.Close()
	return buf.String(), nil
}

func parseDERFromPEM(pemDataId string, blockType string) (*pem.Block, error) {
	readBytes, err := os.ReadFile(pemDataId)
	if err != nil {
		return nil, err
	}

	var block *pem.Block
	for len(readBytes) > 0 {
		block, readBytes = pem.Decode(readBytes)
		if block == nil {
			return nil, errors.New("unable to parse PEM data")
		}
		if block.Type == blockType {
			return block, nil
		}
	}
	return nil, errors.New("requested block type could not be found")
}

func readPKCS8PrivateKey(privateKeyId string, passphrase string) (crypto.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return nil, errors.New("could not parse PEM data")
	}

	privateKey, err := pkcs8.ParsePKCS8PrivateKeyRSA(block.Bytes, []byte(passphrase))

	if err != nil {
		return nil, errors.New("could not parse private key")
	}

	return privateKey, nil
}

// readPrivateKeyData Load the private key referenced by `privateKeyId`.
func readPrivateKeyData(privateKeyId, passphrase string) (crypto.PrivateKey, error) {
	if key, err := readPKCS8PrivateKey(privateKeyId, passphrase); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse private key")
}

// readCertificateData loads the certificate referenced by `certificateId` and extracts
// details required by the SDK to construct the StringToSign.
func readCertificateData(certificateId string) (CertificateData, *x509.Certificate, error) {
	block, err := parseDERFromPEM(certificateId, "CERTIFICATE")
	if err != nil {
		return CertificateData{}, nil, errors.New("could not parse PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateData{}, nil, errors.New("could not parse certificate")
	}

	//extract serial number
	serialNumber := cert.SerialNumber.String()

	//encode certificate
	encodedDer, _ := encodeDer(block.Bytes)

	//extract key type
	var keyType string
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
	default:
		keyType = ""
	}

	supportedAlgorithms := []string{
		fmt.Sprintf("%sSHA256", keyType),
		fmt.Sprintf("%sSHA384", keyType),
		fmt.Sprintf("%sSHA512", keyType),
	}

	//return struct
	return CertificateData{keyType, encodedDer, serialNumber, supportedAlgorithms}, cert, nil
}
