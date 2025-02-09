package aws_rolesanywhere

type Options struct {
	Endpoint             string
	PrivateKeyFile       string
	CertificateFile      string
	PrivateKeyPassphrase string
}

type RolesAnywhere struct {
	signer        Signer
	signAlgorithm string
	endpoint      string
}

// New creates a new instance of the RolesAnywhere client with a session.
func New(opts Options) (*RolesAnywhere, error) {

	signer, signAlgorithm, err := getFileSystemSigner(opts.PrivateKeyFile, opts.CertificateFile, opts.PrivateKeyPassphrase)
	if err != nil {
		return nil, err
	}

	return &RolesAnywhere{
		endpoint:      opts.Endpoint,
		signer:        signer,
		signAlgorithm: signAlgorithm,
	}, nil
}
