package data

import (
	"github.com/rubblelabs/ripple/crypto"
)

func Sign(s Signable, key crypto.Key, sequence *uint32) error {
	s.InitialiseForSigning()
	copy(s.GetPublicKey().Bytes(), key.Public(sequence))
	hash, msg, err := SigningHash(s)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(key.Private(sequence), hash.Bytes(), append(s.SigningPrefix().Bytes(), msg...))
	if err != nil {
		return err
	}
	*s.GetSignature() = VariableLength(sig)
	hash, _, err = Raw(s)
	if err != nil {
		return err
	}
	copy(s.GetHash().Bytes(), hash.Bytes())
	return nil
}

func MultiSign(s *Payment, key crypto.Key, sequence *uint32, signerAccount Account) error {
	s.InitialiseForMultiSigning()
	hash, msg, err := MultiSignHash(s, signerAccount)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(key.Private(sequence), hash.Bytes(), append(s.SigningPrefix().Bytes(), msg...))
	if err != nil {
		return err
	}
	signer := Signer{}
	signer.Signer.Account = signerAccount
	signer.Signer.TxnSignature = new(VariableLength)
	*signer.Signer.TxnSignature = VariableLength(sig)
	pub := new(PublicKey)
	copy(pub[:], key.Public(sequence))
	signer.Signer.SigningPubKey = pub
	s.Signers = append(s.Signers, signer)

	return nil
}

func CheckSignature(s Signable) (bool, error) {
	hash, msg, err := SigningHash(s)
	if err != nil {
		return false, err
	}
	return crypto.Verify(s.GetPublicKey().Bytes(), hash.Bytes(), msg, s.GetSignature().Bytes())
}

func CheckMultiSignature(s Signable, signer Account, signerPk, signature []byte) (bool, error) {
	hash, msg, err := MultiSignHash(s, signer)
	if err != nil {
		return false, err
	}
	return crypto.Verify(signerPk, hash.Bytes(), msg, signature)
}
