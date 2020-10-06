package cryptopals

import (
    "log"
    "crypto/rand"
    "math/big"
)

type DiffieHellman struct {
    g *big.Int
    p *big.Int
    secret_key *big.Int
}

func (dh *DiffieHellman) get_public_key() *big.Int {
    s_k, err := rand.Int(rand.Reader, dh.p)
    if err != nil{
        log.Fatal()
    }
    dh.secret_key = s_k
    public_key := new(big.Int).Exp(dh.g, dh.secret_key, dh.p)
    return public_key
}

func (dh *DiffieHellman) get_shared_secret_key(public_key *big.Int) *big.Int {
    return new(big.Int).Exp(public_key, dh.secret_key, dh.p)
}
