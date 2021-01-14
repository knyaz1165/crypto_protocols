package cryptopals

import (
    "math"
    "math/big"
    "crypto/rand"
    "github.com/ghhenry/intfact"
    "crypto/sha1"
)

var default_P, _ =  new(big.Int).SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)
var default_G, _ =  new(big.Int).SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)
var q, _ = new(big.Int).SetString("236234353446506858198510045061214171961", 10)

var alice_secret,_ = rand.Int(rand.Reader, q)
var bob_secret,_ = rand.Int(rand.Reader, q)

var big0 = big.NewInt(0)

		

type factor struct {
	fact *big.Int
	exp  int64
}

func factorize(n *big.Int) []factor {
	factors := make([]factor, 0)
	l := intfact.NewFactors(n)
	l.TrialDivision(math.MaxUint32)
	for p := l.First; p != nil; p = p.Next {
		factors = append(factors, factor{
			p.Fac, int64(p.Exp),
		})
	}
	return factors
}


func MAC(K *big.Int,m string) []byte{
    var b = 64
    var ipad = ""
    var opad = ""
    var zero = ""
    var key string
    for i:=0;i<b;i++{
        ipad = ipad + "54"
        opad = opad + "92"
        if i<44{
            zero = zero + "0"
        }
    }
    
    var s0 []byte = K.Bytes()
    if len(s0) != b{
        q := sha1.Sum(s0)
        key = string(q[:]) + zero
    }else {
        key = string(K.Bytes())
    }
    
    ikeypad := xor([]byte(key),[]byte(ipad))
    k_ipad := string(ikeypad) + m
    q := sha1.Sum([]byte(k_ipad))
    okeypad := string(xor([]byte(key),[]byte(opad))) + string(q[:])
    q = sha1.Sum([]byte(okeypad))
    
    return q[:]
}


func subgroup_confinement_attacks(alice DiffieHellman,bob DiffieHellman) *big.Int{
    pminus1 := new(big.Int).Sub(default_P, big1)
//     j := new(big.Int).Div(pminus1,big1)
     var gotFactors = []factor{
 			{big.NewInt(2), 1},
 			{big.NewInt(3), 2},
 			{big.NewInt(5), 1},
 			{big.NewInt(109), 1},
 			{big.NewInt(7963), 1},
 			{big.NewInt(8539), 1},
 			{big.NewInt(20641), 1},
 			{big.NewInt(38833), 1},
 			{big.NewInt(39341), 1},
 			{big.NewInt(46337), 1},
 			{big.NewInt(51977), 1},
 			{big.NewInt(54319), 1},
 			{big.NewInt(57529), 1},
			{big.NewInt(96142199), 1},
     }
    
//     gotFactors := factorize(j)
    m := "crazy flamboyant for the rap enjoyment"
    var h *big.Int
    flag := true
    var t []byte
    var bi = []factor{}
    var ri = []factor{}
    var mul = big1
    
    for i:=0; i<len(gotFactors) && flag == true && mul.Cmp(q) != 1;  i++{
        var l *big.Int
        var r  = gotFactors[i].fact
        var f = false
        for f!=true{
            var random, _ = rand.Int(rand.Reader, default_P)
            var degree = new(big.Int).Div(pminus1,r)
            h = new(big.Int).Exp(random, degree, default_P)
            
            if h.Cmp(big1) != 0{
                f = true
            }
        }
        K := bob.get_shared_secret_key(h)
        t = MAC(K,m)
        
        var key *big.Int
        for l=big2; l.Cmp(r) != 0; {
            
            key = new(big.Int).Exp(h, l, default_P)
            mac := MAC(key,m)
            
            if string(mac) == string(t) {
                bi = append(bi, factor{
                l,1})
                ri = append(ri, factor{
                r,1})
                mul = new(big.Int).Mul(mul,r)
                break
            }

            l=new(big.Int).Add(l, big1)
            
        }
        
    }
    
    var M0 = mul
    var mi = []factor{}
    var yi = []factor{}
    
    for i:=0; i<len(ri); i++ {
        mi = append(mi, factor{new(big.Int).Div(M0,ri[i].fact),1})
    }
    

    for i:=0; i<len(mi); i++{
        e := new(big.Int).Sub(ri[i].fact, big2)
        yi = append(yi, factor{new(big.Int).Exp(mi[i].fact,e,ri[i].fact),1})
    }

    
    var x *big.Int = big0
    for i:=0; i<len(mi); i++{
        e := new(big.Int).Mul(mi[i].fact,yi[i].fact)
        d := new(big.Int).Mul(bi[i].fact, e)
        x = new(big.Int).Add(x,d)
    }
        

    x = new(big.Int).Exp(x, big1, M0)
    return x
}
    
    



