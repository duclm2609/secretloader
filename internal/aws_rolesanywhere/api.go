package aws_rolesanywhere

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

const SingaporeRegionalEndpoint = "https://rolesanywhere.ap-southeast-1.amazonaws.com"

const (
	x_amz_date = "X-Amz-Date"
	x_amz_x509 = "X-Amz-X509"
)

type CreateSessionInput struct {
	ProfileArn      string `json:"profileArn"`
	SessionName     string `json:"sessionName"`
	TrustAnchorArn  string `json:"trustAnchorArn"`
	RoleArn         string `json:"roleArn"`
	DurationSeconds int    `json:"durationSeconds"`
}

// CreateSessionOutput represents the top-level JSON structure
type CreateSessionOutput struct {
	CredentialSet []CredentialSet `json:"credentialSet"`
	SubjectArn    string          `json:"subjectArn"`
}

// CredentialSet represents each credential set in the array
type CredentialSet struct {
	AssumedRoleUser  AssumedRoleUser `json:"assumedRoleUser"`
	Credentials      Credentials     `json:"credentials"`
	PackedPolicySize int             `json:"packedPolicySize"`
	RoleArn          string          `json:"roleArn"`
	SourceIdentity   string          `json:"sourceIdentity"`
}

// AssumedRoleUser represents assumed role user details
type AssumedRoleUser struct {
	Arn           string `json:"arn"`
	AssumedRoleId string `json:"assumedRoleId"`
}

// Credentials holds AWS credentials information
type Credentials struct {
	AccessKeyID     string    `json:"accessKeyId"`
	Expiration      time.Time `json:"expiration"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
}

// CreateSession API operation for RolesAnywhere Service.
func (c *RolesAnywhere) CreateSession(input *CreateSessionInput) (*CreateSessionOutput, error) {
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", "", bytes.NewReader(reqBody))
	if err != nil {
		panic(err)
	}

	if c.endpoint == "" {
		req.URL, _ = url.Parse(SingaporeRegionalEndpoint)
	} else {
		req.URL, err = url.Parse(c.endpoint)
		if err != nil {
			return nil, err
		}
	}
	req.URL.Path = "/sessions"

	// Sign the request
	signerParams := SignerParams{
		OverriddenDate:   time.Now(),
		RegionName:       "ap-southeast-1",
		ServiceName:      "rolesanywhere",
		SigningAlgorithm: c.signAlgorithm,
	}

	certificate, err := c.signer.Certificate()
	if err != nil {
		return nil, errors.New("unable to find certificate")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(x_amz_date, signerParams.GetFormattedSigningDateTime())
	req.Header.Set(x_amz_x509, certificateToString(certificate))

	reqBodySeeker, err := bodyToReadSeeker(req.Body)
	if err != nil {
		return nil, err
	}
	contentSha256 := calculateContentHash(req, reqBodySeeker)

	canonicalRequest, signedHeadersString := createCanonicalRequest(req, reqBodySeeker, contentSha256)

	// ************* CALCULATE THE SIGNATURE *************
	stringToSign := createStringToSign(canonicalRequest, signerParams)
	signatureBytes, err := c.signer.Sign(rand.Reader, []byte(stringToSign), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	signature := hex.EncodeToString(signatureBytes)

	// ************* ADD SIGNING INFORMATION TO THE REQUEST *************
	authorizationHeader := buildAuthorizationHeader(signedHeadersString, signature, certificate, signerParams)

	req.Header.Set(authorization, authorizationHeader)

	// ************* SEND REQUEST *************
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var credResponse CreateSessionOutput
	err = json.Unmarshal(body, &credResponse)
	if err != nil {
		return nil, err
	}
	return &credResponse, nil
}
