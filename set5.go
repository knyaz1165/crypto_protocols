package cryptopals

import (
    "math/big"
    "crypto/rand"
    "crypto/aes"
    "crypto/sha1"
    "log"
)


type DiffieHellman struct {
    g *big.Int
    p *big.Int
    secret_key *big.Int
}

func (dh *DiffieHellman) get_public_key() *big.Int {
    public_key := new(big.Int).Exp(dh.g, dh.secret_key, dh.p)
    return public_key
}

func (dh *DiffieHellman) get_shared_secret_key(public_key *big.Int) *big.Int {
    return new(big.Int).Exp(public_key, dh.secret_key, dh.p)
}


func xor(s1 []byte, s2 []byte) []byte{
    result := make([]byte, len(s1))
    for i := 0; i < len(s1); i++ {
        result[i] = s1[i] ^ s2[i]
    }
    return result
}


func pkcs7_padding(data []byte, block_size int) []byte {
    if len(data) % block_size == 0 {
        return data
    }
    
    padding_len := block_size - len(data) % block_size
    
    result := make([]byte, len(data) + padding_len)
    copy(result, data)
    
    for i := len(data); i < len(result); i++ {
        result[i] = byte(padding_len)
    }
    
    return result
}

func pkcs7_unpad(data []byte) []byte {
    if int(data[len(data) - 1]) > 0 && int(data[len(data) - 1]) < 16{
        return data[:len(data) - int(data[len(data) - 1])]
    }
    return data
}

func aes_ecb_encrypt(data, key []byte) []byte {
	aes_block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal()
	}
	
	block_size := aes_block.BlockSize()
	data = pkcs7_padding(data, block_size)
	if len(data) % block_size != 0 {
		log.Fatal()
	}
	
	ciphertext := make([]byte, len(data))
    
	for i := 0; i < len(data); i += block_size {
		aes_block.Encrypt(ciphertext[i:i + block_size], data[i:i + block_size])
	}
	return ciphertext
}

func aes_ecb_decrypt(cipher, key []byte) []byte {
	aes_block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal()
	}
	
	data := make([]byte, len(cipher))

	block_size := aes_block.BlockSize()
	if len(cipher) % block_size != 0 {
		log.Fatal()
	}
	for i := 0; i < len(cipher); i += block_size {
		aes_block.Decrypt(data[i:i + block_size], cipher[i:i + block_size])
	}

	return data
}



func aes_cbc_encrypt(data []byte, key []byte, iv []byte) []byte{
    aes_block, err := aes.NewCipher(key)
    if err != nil {
		log.Fatal()
	}
    block_size := aes_block.BlockSize()
	data = pkcs7_padding(data, block_size)
    
    ciphertext := make([]byte, len(data))
    prev_block := iv
    
    for i := 0; i < len(data); i += block_size {
        copy(ciphertext[i:i + block_size], aes_ecb_encrypt(xor(data[i:i + block_size], prev_block), key))
        prev_block = ciphertext[i:i + block_size]
    }
    
    return ciphertext
}


func aes_cbc_decrypt(ciphertext []byte, key []byte, iv []byte) []byte{
    aes_block, err := aes.NewCipher(key)
    if err != nil {
        log.Fatal()
    }
    block_size := aes_block.BlockSize()
    data := make([]byte, len(ciphertext))
    prev_block := iv
    
    for i := 0; i < len(ciphertext); i += block_size{
        copy(data[i:i + block_size], aes_ecb_decrypt(ciphertext[i:i + block_size],key))
        copy(data[i:i + block_size],xor(data[i:i + block_size], prev_block))
        prev_block = ciphertext[i:i + block_size]
    }
    
    return pkcs7_unpad(data)
}

func parameter_injection_attack(alice DiffieHellman, bob DiffieHellman) bool {
    
    
    A := alice.get_public_key()
    A = alice.p
    B := bob.get_public_key()
    B = bob.p

    alice_message := []byte("Hello, Bob! How are you today? What are you doing?")
    
    sum := sha1.Sum(alice.get_shared_secret_key(B).Bytes())
    alice_key := sum[:16]
    
    var alice_iv = make([]byte, 16)
    rand.Read(alice_iv)
    alice_cipher := aes_cbc_encrypt(alice_message, alice_key[:16], alice_iv)
    
    //Алиса отправляет cyphertext_for_bob
    cyphertext_for_bob := string(alice_cipher) + string(alice_iv)
    
    sum = sha1.Sum(bob.get_shared_secret_key(A).Bytes())
    bob_key := sum[:16]
    
    //Боб принимает cyphertext_for_bob и находит iv Алисы
    a_iv := []byte(cyphertext_for_bob[len(cyphertext_for_bob) - 16:])
    
    //Боб расшифровывает
    message_from_alice := aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), bob_key, a_iv)
    
    bob_iv := make([]byte, 16)
    rand.Read(bob_iv)
    
    msg_for_alice := string(aes_cbc_encrypt(message_from_alice, bob_key, bob_iv)) + string(bob_iv)
    
    //При A=B=p общий секрет Алисы и Боба будет = 0
    mitm_key := sha1.Sum(big.NewInt(0).Bytes())
    mitm_iv_alice := []byte(cyphertext_for_bob[len(cyphertext_for_bob) - 16:])
    hacked_msg_alice := string(aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), mitm_key[:16], mitm_iv_alice))
    
    
    mitm_iv_bob := []byte(msg_for_alice[len(msg_for_alice) - 16:])
    hacked_msg_bob := string(aes_cbc_decrypt([]byte(msg_for_alice[:len(msg_for_alice) - 16]), mitm_key[:16], mitm_iv_bob))
    
    return hacked_msg_alice == hacked_msg_bob
    
}

func malicious_g_attack(alice DiffieHellman, bob DiffieHellman) bool{
    
    p := alice.p
    g := alice.g
    
    B := bob.get_public_key()
    
    alice_message := []byte("Hello, Bob! How are you today? What are you doing?")
    
    sum := sha1.Sum(alice.get_shared_secret_key(B).Bytes())
    alice_key := sum[:16]
    
    var alice_iv = make([]byte, 16)
    rand.Read(alice_iv)
    alice_cipher := aes_cbc_encrypt(alice_message, alice_key, alice_iv)
    
    //Алиса отправляет cyphertext_for_bob
    cyphertext_for_bob := string(alice_cipher) + string(alice_iv)
    
    mitm_iv_alice := []byte(cyphertext_for_bob[len(cyphertext_for_bob) - 16:])
    
    //При g=1 общий секрет Алисы и Боба будет = 1
    if g.Cmp(big1) == 0 {
        mitm_key := sha1.Sum(big1.Bytes())
        hacked_msg_alice := string(aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), mitm_key[:16], mitm_iv_alice))
        
        if hacked_msg_alice == string(alice_message){
            return true
        }
    }
    
    //При g=p общий секрет АЛисы и Боба будет = 0
    if g.Cmp(p) == 0 {
        mitm_key := sha1.Sum(big.NewInt(0).Bytes())
        hacked_msg_alice := string(aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), mitm_key[:16], mitm_iv_alice))

        if hacked_msg_alice == string(alice_message){
            return true
        }
    }
    
    // При g=p-1 общий секрет АЛисы и Боба будет = либо 1
    if g.Cmp(pminus1) == 0 {
        mitm_key := sha1.Sum(big1.Bytes())
        hacked_msg_alice := string(aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), mitm_key[:16], mitm_iv_alice))

        if hacked_msg_alice == string(alice_message){
            return true
        }
        
        //либо -1
        mitm_key = sha1.Sum(pminus1.Bytes())
        hacked_msg_alice = string(aes_cbc_decrypt([]byte(cyphertext_for_bob[:len(cyphertext_for_bob) - 16]), mitm_key[:16], mitm_iv_alice))

        if hacked_msg_alice == string(alice_message){
            return true
        }
    }
    
    return false
}
