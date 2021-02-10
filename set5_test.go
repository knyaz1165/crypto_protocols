package cryptopals

import (
    "math/big"
    "testing"
    "crypto/rand"
)


var default_p, err = new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)    

var big1 = big.NewInt(1)
var big2 = big.NewInt(2)
var big3 = big.NewInt(3)

var pminus1 = new(big.Int).Sub(default_p, big1)
var a,errr = rand.Int(rand.Reader, default_p)
var b,errrr = rand.Int(rand.Reader, default_p)


func Test_33(t *testing.T){
    
    var g = big2
    
    alice := DiffieHellman{g, default_p, a}
    bob := DiffieHellman{g, default_p, b}
    
    A := alice.get_public_key()
    B := bob.get_public_key()
    
    s_alice := alice.get_shared_secret_key(B)
    s_bob := bob.get_shared_secret_key(A)
    
    if s_alice.Cmp(s_bob) != 0 {
        t.Error("Error")
    }
}


func Test_34(t *testing.T) {
    
    var g = big2
    
    alice := DiffieHellman{g, default_p, a}
    bob := DiffieHellman{g, default_p, b}
    
    if !parameter_injection_attack(alice, bob) {
        t.Error("Error")
    }
    
}


func Test_35(t *testing.T) {
    var g = big1
    
    alice := DiffieHellman{g, default_p, a}
    bob := DiffieHellman{g, default_p, b}
    
    if !malicious_g_attack(alice, bob){
        t.Error("Error")
    }
    
    g = default_p
    
    alice = DiffieHellman{g, default_p, a}
    bob = DiffieHellman{g, default_p, b}
    
    if !malicious_g_attack(alice, bob){
        t.Error("Error")
    }
    
    g = pminus1
    
    alice = DiffieHellman{g, default_p, a}
    bob = DiffieHellman{g, default_p, b}
    
    if !malicious_g_attack(alice, bob){
        t.Error("Error")
    }
}
