package secretloader

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/duclm2609/secretloader/internal/aws_rolesanywhere"
	"log"
	"reflect"
	"strconv"
)

const (
	awsRegion     string = "ap-southeast-1"
	secretTagName string = "awssecretmanager"
)

type AwsRoleAnywhereConfig struct {
	PrivateKeyPath       string
	PrivateKeyPassphrase string
	CertificatePath      string
	ProfileArn           string
	RoleArn              string
	SessionName          string
	TrustAnchorArn       string
	DurationSeconds      int
	Endpoint             string
}

type Options struct {
	SecretName         string
	RoleAnywhereConfig *AwsRoleAnywhereConfig
}

type SecretsLoader struct {
	client *secretsmanager.Client
	opts   Options
}

func NewSecretsLoader(opts Options) (*SecretsLoader, error) {
	if opts.RoleAnywhereConfig == nil {
		awsCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(awsRegion))
		if err != nil {
			return nil, err
		}

		return &SecretsLoader{
			client: secretsmanager.NewFromConfig(awsCfg),
			opts:   opts,
		}, nil
	}

	// Load secrets with credentials from AWS IAM Role Anywhere
	rolesanywhere, err := aws_rolesanywhere.New(aws_rolesanywhere.Options{
		Endpoint:             opts.RoleAnywhereConfig.Endpoint,
		PrivateKeyFile:       opts.RoleAnywhereConfig.PrivateKeyPath,
		CertificateFile:      opts.RoleAnywhereConfig.CertificatePath,
		PrivateKeyPassphrase: opts.RoleAnywhereConfig.PrivateKeyPassphrase,
	})

	if err != nil {
		return nil, err
	}
	session, err := rolesanywhere.CreateSession(&aws_rolesanywhere.CreateSessionInput{
		ProfileArn:      opts.RoleAnywhereConfig.ProfileArn,
		SessionName:     opts.RoleAnywhereConfig.SessionName,
		TrustAnchorArn:  opts.RoleAnywhereConfig.TrustAnchorArn,
		RoleArn:         opts.RoleAnywhereConfig.RoleArn,
		DurationSeconds: opts.RoleAnywhereConfig.DurationSeconds,
	})
	if err != nil {
		return nil, err
	}
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(awsRegion),
		config.WithCredentialsProvider(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     session.CredentialSet[0].Credentials.AccessKeyID,
				SecretAccessKey: session.CredentialSet[0].Credentials.SecretAccessKey,
				SessionToken:    session.CredentialSet[0].Credentials.SessionToken,
			}, nil
		})))
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	return &SecretsLoader{
		client: secretsmanager.NewFromConfig(awsCfg),
		opts:   opts,
	}, nil
}

func (s *SecretsLoader) LoadSecrets(target interface{}) error {
	val := reflect.ValueOf(target)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return errors.New("target must be a pointer to a struct")
	}

	val = val.Elem()
	typ := val.Type()

	resp, err := s.client.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(s.opts.SecretName),
	})
	if err != nil {
		return err
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		secretKey := field.Tag.Get(secretTagName)
		if secretKey == "" {
			continue
		}

		secretValue, err := s.getSecretValue(resp, secretKey)
		if err != nil {
			return err
		}

		if err := setField(val.Field(i), secretValue); err != nil {
			return err
		}
	}

	return nil
}

func (s *SecretsLoader) getSecretValue(resp *secretsmanager.GetSecretValueOutput, jsonKey string) (string, error) {
	if jsonKey == "" {
		return *resp.SecretString, nil
	}

	var secretData map[string]string
	if err := json.Unmarshal([]byte(*resp.SecretString), &secretData); err != nil {
		return "", err
	}

	value, exists := secretData[jsonKey]
	if !exists {
		return "", errors.New("specified key not found in secret")
	}

	return value, nil
}

func setField(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		field.SetInt(intVal)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		field.SetBool(boolVal)
	case reflect.Float32, reflect.Float64:
		doubleVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		field.SetFloat(doubleVal)
	default:
		return errors.New("unsupported field type")
	}
	return nil
}
