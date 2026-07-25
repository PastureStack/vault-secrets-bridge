package broker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func encryptLeaseRecord(publicKey *rsa.PublicKey, request issueRequest, token []byte) (encryptedRecord, error) {
	if publicKey == nil || publicKey.N.BitLen() < 2048 || len(token) == 0 || len(token) > 64<<10 {
		return encryptedRecord{}, errors.New("Vault lease encryption input is invalid")
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return encryptedRecord{}, errors.New("unable to create Vault lease encryption key")
	}
	defer zeroBytes(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return encryptedRecord{}, errors.New("unable to create Vault lease cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedRecord{}, errors.New("unable to create Vault lease cipher")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return encryptedRecord{}, errors.New("unable to create Vault lease nonce")
	}
	clearText := make([]byte, base64.StdEncoding.EncodedLen(len(token)))
	base64.StdEncoding.Encode(clearText, token)
	cipherText := gcm.Seal(nil, nonce, clearText, nil)
	zeroBytes(clearText)
	payload, err := json.Marshal(aesEnvelope{
		Nonce:      nonce,
		Algorithm:  "aes256-gcm",
		CipherText: cipherText,
	})
	if err != nil {
		return encryptedRecord{}, errors.New("unable to encode Vault lease payload")
	}
	signingNonce := make([]byte, 12)
	if _, err := rand.Read(signingNonce); err != nil {
		return encryptedRecord{}, errors.New("unable to create Vault lease signature nonce")
	}
	mac := hmac.New(sha256.New, dataKey)
	_, _ = mac.Write(signingNonce)
	_, _ = mac.Write([]byte(":"))
	_, _ = mac.Write(payload)
	signature := append(append(append([]byte(nil), signingNonce...), ':'), mac.Sum(nil)...)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dataKey, nil)
	if err != nil {
		return encryptedRecord{}, errors.New("unable to protect Vault lease encryption key")
	}
	envelope, err := json.Marshal(encryptedEnvelope{
		EncryptionAlgorithm: "aes256-gcm96",
		EncryptedText:       string(payload),
		EncryptedKey: rsaEnvelope{
			EncryptionAlgorithm: "PKCS1_OAEP",
			EncryptedText:       base64.StdEncoding.EncodeToString(encryptedKey),
			HashAlgorithm:       "sha256",
		},
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return encryptedRecord{}, errors.New("unable to encode Vault lease envelope")
	}
	return encryptedRecord{
		Name:       request.File,
		UID:        request.UID,
		GID:        request.GID,
		Mode:       request.Mode,
		RewrapText: base64.StdEncoding.EncodeToString(envelope),
	}, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
