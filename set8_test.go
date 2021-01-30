package cryptopals

import (
    "fmt"
	"crypto/rand"
	"math/big"
	"testing"
)

type kangarooTest struct {
	p, g, y, a, b string
}

var kangarooTests = []kangarooTest{
   	{"11", "2", "9", "1", "10"},
   	{"99989", "8", "428", "1", "99989"},
	{
		"11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623",
		"622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357",
		"7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119",
		"1",
		"1048576",
	},
}

func Test_57(t *testing.T) {
	var p, _ = new(big.Int).SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
	var g, _ = new(big.Int).SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)
	var q, _ = new(big.Int).SetString("236234353446506858198510045061214171961", 10)

	//     var alice_secret,_ = rand.Int(rand.Reader, q)
	var bob_secret, _ = rand.Int(rand.Reader, q)

	//     alice := DiffieHellman{g,p,alice_secret}
	bob := DiffieHellman{g, p, bob_secret}

	e := new(big.Int).Exp(g, q, p)
	if e.Cmp(big1) != 0 {
		t.Fatalf("%s: g^q != 1 mod p", t.Name())
	}

	pminus1 := new(big.Int).Sub(p, big1)
	cofactor := new(big.Int).Div(pminus1, q)

	hacked_key, _ := DHSmallSubgroupAttack(p, cofactor, q, bob)

	if bob_secret.Cmp(hacked_key) != 0 {
		t.Error("Error")
	}
}

func Test_58(t *testing.T) {
	for _, e := range kangarooTests {
		p, _ := new(big.Int).SetString(e.p, 10)
		g, _ := new(big.Int).SetString(e.g, 10)
		y, _ := new(big.Int).SetString(e.y, 10)
		a, _ := new(big.Int).SetString(e.a, 10)
		b, _ := new(big.Int).SetString(e.b, 10)

		x := catchKangaroo(p, g, y, a, b)
		if new(big.Int).Exp(g, x, p).Cmp(y) != 0 {
			t.Fatalf("%s: (%d, %d, %d, %d, %d) failed", t.Name(), p, g, y, a, b)
		}
	}
	
	p, _ := new(big.Int).SetString("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10)
	g, _ := new(big.Int).SetString("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10)
	q, _ := new(big.Int).SetString("335062023296420808191071248367701059461", 10)
	// p-1 = q*cofactor
	cofactor, _ := new(big.Int).SetString("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702", 10)
        
    var bob_secret, _ = rand.Int(rand.Reader, q)
    bob := DiffieHellman{g,p,bob_secret}

	x := DHKangarooAttack(p, g, q, cofactor, bob)

	if bob_secret.Cmp(x) != 0{
		t.Fatalf("%s: wrong private key was found in the sugbroup attack", t.Name())
	}
	fmt.Printf("%s: Found key: %d\n", t.Name(), x)
}
