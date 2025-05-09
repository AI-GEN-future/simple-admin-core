package sm2go

import (
	"context"
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/zeromicro/go-zero/core/logx"
)

type Sm2Go struct {
	logger     logx.Logger
	privateKey *sm2.PrivateKey
	publicKey  *sm2.PublicKey
}

func NewSm2Go(privateKey string) (*Sm2Go, error) {
	priKey, err := x509.ReadPrivateKeyFromHex(privateKey)
	if err != nil {
		return nil, err
	}
	return &Sm2Go{
		logger:     logx.WithContext(context.Background()),
		privateKey: priKey,
		publicKey:  &priKey.PublicKey,
	}, nil
}

func (s *Sm2Go) Sm2Encrypt(data string) (string, error) {
	encrypt, err := sm2.Encrypt(s.publicKey, []byte(data), rand.Reader, sm2.C1C3C2)
	if err != nil {
		s.logger.Errorf("加密失败: %v\n", err)
		return "", err
	}
	return string(encrypt), nil
}

func (s *Sm2Go) Sm2Decrypt(ciphertext string) (string, error) {
	decrypted, err := sm2.Decrypt(s.privateKey, []byte(ciphertext), sm2.C1C3C2) // 解密
	if err != nil {
		s.logger.Errorf("解密失败: %v\n", err)
		return "", err
	}
	return string(decrypted), nil
}
