package cryptopals

import (
    "testing"
)


func Test_57(t *testing.T){
    
    alice := DiffieHellman{default_G,default_P,alice_secret}
    bob := DiffieHellman{default_G,default_P,bob_secret}
    
    hacked_key := subgroup_confinement_attacks(alice,bob)
    
    if bob_secret.Cmp(hacked_key) != 0{
        t.Error("Error")
    }
}
