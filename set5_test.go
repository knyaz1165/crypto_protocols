package cryptopals

import (
    "math/big"
    "testing"
    "log"
)


func Test_33(t *testing.T){
    
    var p, err = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
    var g = big.NewInt(2)
    
    if err != true{
        log.Fatal()
    }
    
    alice := DiffieHellman{g, p, nil}
    bob := DiffieHellman{g, p, nil}
    
    A := alice.get_public_key()
    B := bob.get_public_key()
    
    s_alice := alice.get_shared_secret_key(B)
    s_bob := bob.get_shared_secret_key(A)
    
    if s_alice.Cmp(s_bob) != 0 {
        t.Error("Error")
    }
}
