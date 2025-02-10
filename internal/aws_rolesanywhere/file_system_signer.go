package aws_rolesanywhere

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"os"
)

type FileSystemSigner struct {
	certPath       string
	privateKeyPath string
	passphrase     string
}

func (fileSystemSigner *FileSystemSigner) Public() crypto.PublicKey {
	privateKey, _ := fileSystemSigner.readCertFiles()
	{
		privateKey, ok := privateKey.(rsa.PrivateKey)
		if ok {
			return &privateKey.PublicKey
		}
	}
	return nil
}

func (fileSystemSigner *FileSystemSigner) Close() {}

func (fileSystemSigner *FileSystemSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	privateKey, _ := fileSystemSigner.readCertFiles()
	var hash []byte
	switch opts.HashFunc() {
	case crypto.SHA256:
		sum := sha256.Sum256(digest)
		hash = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(digest)
		hash = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(digest)
		hash = sum[:]
	default:
		return nil, ErrUnsupportedHash
	}

	rsaPrivateKey, ok := privateKey.(rsa.PrivateKey)
	if ok {
		sig, err := rsa.SignPKCS1v15(rand, &rsaPrivateKey, opts.HashFunc(), hash[:])
		if err == nil {
			return sig, nil
		}
	}

	log.Println("unsupported algorithm")
	return nil, errors.New("unsupported algorithm")
}

func (fileSystemSigner *FileSystemSigner) Certificate() (*x509.Certificate, error) {
	_, cert := fileSystemSigner.readCertFiles()
	return cert, nil
}

// getFileSystemSigner returns a FileSystemSigner, that signs a payload using the private key passed in
func getFileSystemSigner(privateKeyPath string, certPath string, passphrase string) (signer Signer, signingAlgorithm string, err error) {
	fsSigner := &FileSystemSigner{certPath: certPath, privateKeyPath: privateKeyPath, passphrase: passphrase}
	privateKey, _ := fsSigner.readCertFiles()
	// Find the signing algorithm
	_, isRsaKey := privateKey.(*rsa.PrivateKey)
	if isRsaKey {
		signingAlgorithm = aws4X509RsaSha256
	}
	if signingAlgorithm == "" {
		return nil, "", errors.New("unsupported algorithm")
	}

	if passphrase == "" {
		return nil, "", errors.New("passphrase must not be empty")
	}

	return fsSigner, signingAlgorithm, nil
}

func (fileSystemSigner *FileSystemSigner) readCertFiles() (crypto.PrivateKey, *x509.Certificate) {
	privateKey, err := readPrivateKeyData(fileSystemSigner.privateKeyPath, fileSystemSigner.passphrase)
	if err != nil {
		log.Printf("Failed to read private key: %s\n", err)
		os.Exit(1)
	}
	var cert *x509.Certificate
	if fileSystemSigner.certPath != "" {
		_, cert, err = readCertificateData(fileSystemSigner.certPath)
		if err != nil {
			privateKey = nil
			log.Printf("Failed to read certificate: %s\n", err)
			os.Exit(1)
		}
	} else {
		log.Println("No certificate path or certificate bundle path provided")
		os.Exit(1)
	}

	return privateKey, cert
}
