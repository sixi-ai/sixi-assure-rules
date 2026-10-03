package tsp

import "crypto/x509"

// VerifyUnrooted checks a token as Verify does — the imprint over headHash, the CMS signature, the
// signed attributes, the signing-certificate binding and the time-stamping usage at genTime —
// except that the chain ends at the certificates the token and certChain carry instead of a root
// the caller trusts. ChainVerified is false: the result shows integrity, not who the authority is.
// The offline verifier uses it when no roots are given and the platform's root store cannot be read
// without the operating system's verifier (which may go online).
func VerifyUnrooted(token, certChain []byte, headHash string) (TokenInfo, error) {
	p, err := parseToken(token)
	if err != nil {
		return TokenInfo{}, err
	}
	extra, err := parseCertChain(certChain)
	if err != nil {
		return TokenInfo{}, err
	}
	pool := x509.NewCertPool()
	for _, c := range append(p.certs, extra...) {
		pool.AddCert(c)
	}
	info, err := Verify(token, certChain, headHash, pool)
	info.ChainVerified, info.RootSHA256 = false, ""
	return info, err
}
