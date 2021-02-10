package cryptopals

import (
    "bytes"
    "math"
    "math/big"
    "crypto/rand"
    "crypto/sha256"
    "crypto/hmac"
    
    "github.com/knyaz1165/cryptopals/elliptic"
)

var big0 = big.NewInt(0)

const (
	msg = "crazy flamboyant for the rap enjoyment"
)

// pickRandomPoint picks a random point on given curve
func pickRandomPoint(curve elliptic.Curve, order *big.Int) (x *big.Int, y *big.Int) {
	k := new(big.Int).Div(curve.Params().N, order).Bytes()

	for {
		x, y = elliptic.GeneratePoint(curve)
		x, y = curve.ScalarMult(x, y, k)

		if x.Cmp(big0) == 0 && y.Cmp(big0) == 0 {
			continue
		}

		return
	}
}

// ecdh performs DH with given curve, public and private keys
func ecdh(curve elliptic.Curve, x *big.Int, y *big.Int, privateKey []byte) []byte {
	ssx, ssy := curve.ScalarMult(x, y, privateKey)
	return MAC(elliptic.Marshal(curve, ssx, ssy))
}

// checkDuplicate returns true if no duplicates were found
func checkDuplicate(reminders []*big.Int, modules []*big.Int, r *big.Int, m *big.Int) bool {
	if len(reminders) != len(modules) {
		panic("checkDuplicate: len(reminders) != len(modules)")
	}

	ok := true

	for i := 0; i < len(reminders); i++ {
		if reminders[i].Cmp(r) == 0 && modules[i].Cmp(m) == 0 {
			ok = false
			break
		}
	}

	return ok
}

func NewECDHAttackOracle(curve elliptic.Curve) (
	ecdh func(x, y *big.Int) []byte,
	isKeyCorrect func([]byte) bool,
	getPublicKey func() (x, y *big.Int),
) {
	privateKey, x, y, err := elliptic.GenerateKey(curve, nil)
	if err != nil {
		panic(err)
	}

	ecdh = func(x, y *big.Int) []byte {
		sx, sy := curve.ScalarMult(x, y, privateKey)
		return MAC(elliptic.Marshal(curve, sx, sy))
	}

	isKeyCorrect = func(key []byte) bool {
		i := 0
		for i < len(privateKey) && privateKey[i] == 0 {
			i++
		}

		return bytes.Equal(privateKey[i:], key)
	}

	getPublicKey = func() (*big.Int, *big.Int) {
		return x, y
	}

	return
}

func Factorize(n *big.Int, upperBound *big.Int) []*big.Int {
	factors := make([]*big.Int, 0)

	i := new(big.Int).Set(big2)
	tmp := new(big.Int)
	newN := new(big.Int).Set(n)

	for {
		tmp.Mod(newN, i)

		if tmp.Cmp(big0) == 0 {
			factors = append(factors, new(big.Int).Set(i))
			for tmp.Mod(newN, i).Cmp(big0) == 0 {
				newN.Set(tmp.Div(newN, i))
			}
		}

		if newN.Cmp(big1) == 0 {
			break
		}

		if i.Cmp(upperBound) >= 0 {
			break
		}

		i.Add(i, big1)
	}

	return factors
}

func MAC(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func Chinese_Remainder_Theorem(bi, ri[]*big.Int) (n, r *big.Int){
    r = new(big.Int).Set(big1)
    
    for i:=0; i<len(ri); i++{
        r = new(big.Int).Mul(r,ri[i])
    }
    
    var mi,yi []*big.Int
    
    for i:=0; i<len(ri); i++ {
        mi = append(mi, new(big.Int).Div(r,ri[i]))
    }
    

    for i:=0; i<len(mi); i++{
        e := new(big.Int).Sub(ri[i], big2)
        yi = append(yi, new(big.Int).Exp(mi[i],e,ri[i]))
    }

    
    n = big0
    for i:=0; i<len(mi); i++{
        e := new(big.Int).Mul(mi[i],yi[i])
        d := new(big.Int).Mul(bi[i], e)
        n = new(big.Int).Add(n,d)
    }
        

    n = new(big.Int).Mod(n, r)
    
    return n,r
}


func DHSmallSubgroupAttack(p, cofactor, q *big.Int, bob DiffieHellman) (n,r *big.Int){
    pminus1 := new(big.Int).Sub(p, big1)
    gotFactors := Factorize(cofactor, big.NewInt(1<<16))

    var h *big.Int
    var bi, ri []*big.Int
    
    for i:=0; i<len(gotFactors);  i++{
        var l *big.Int
        var mod  = gotFactors[i]

        for true{
            var random, _ = rand.Int(rand.Reader, p)
            var degree = new(big.Int).Div(pminus1,mod)
            h = new(big.Int).Exp(random, degree, p)
            
            if h.Cmp(big1) != 0{
                break
            }
        }
        K := bob.get_shared_secret_key(h)
        t := MAC(K.Bytes())
        
        var key *big.Int
        for l=big1; l.Cmp(mod) <= 0; l = new(big.Int).Add(l, big1){
            key = new(big.Int).Exp(h, l, p)
            mac := MAC(key.Bytes())
            if string(t) == string(mac) {
                bi = append(bi, l)
                ri = append(ri, mod)
                break
            }
        }
    }

    n,r = Chinese_Remainder_Theorem(bi,ri)
    
    return n,r
}

func f(y, k, p *big.Int) *big.Int {
	// f = 2^(y mod k) mod p
	return new(big.Int).Exp(big2, new(big.Int).Mod(y, k), p)
}

func calcN(p, k *big.Int) *big.Int {
	N := new(big.Int).Set(big0)

	for i := new(big.Int).Set(big0); i.Cmp(k) < 0; i.Add(i, big1) {
		N.Add(N, f(i, k, p))
	}

	N.Div(N, k)

	// see for details: tasks/challenge58.txt:99
	return N.Mul(big.NewInt(4), N)
}

func calcK(a, b *big.Int) *big.Int {
	// k = log2(sqrt(b-a)) + log2(log2(sqrt(b-a))) - 2
	sqrtba := math.Sqrt(float64(new(big.Int).Sub(b, a).Uint64()))
	logSqrt := math.Log2(sqrtba)
	logLogSqrt := math.Log2(logSqrt)
    if new(big.Int).SetUint64(uint64(logSqrt + logLogSqrt - 2)).Cmp(big0) == 0{
        return big.NewInt(11)
    }
	return new(big.Int).SetUint64(uint64(logSqrt + logLogSqrt - 2))
}
    
    
func catchKangaroo(p, g, y, a, b *big.Int) *big.Int{
    
    var k = calcK(a,b)

    xT := new(big.Int).Set(big0)
    yT := new(big.Int).Exp(g, b, p)
    e1 := new(big.Int).Set(big0)
    
    N := calcN(p,k)
    
    for i:=new(big.Int).Set(big0); i.Cmp(N)<0; i = new(big.Int).Add(i, big1) {
        xT = new(big.Int).Add(xT, f(yT,k,p))
        e1 = new(big.Int).Exp(g,f(yT,k,p), p)
        yT = new(big.Int).Mod(new(big.Int).Mul(yT, e1), p)        
        
    }
    
    xW := new(big.Int).Set(big0)
    yW := new(big.Int).Set(y)
    e1 = new(big.Int).Add(b, xT)
    
    for ;xW.Cmp(e1) == -1;{
        xW = new(big.Int).Add(xW, f(yW,k,p))
        yW = new(big.Int).Mul(yW, new(big.Int).Exp(g,f(yW,k,p),p))
        yW = new(big.Int).Mod(yW, p)
        if yW.Cmp(yT) == 0{
            break
        }
    }
    
    if xW.Cmp(e1) != -1{
        return big.NewInt(0)
    }else {
		return new(big.Int).Sub(e1, xW)
	}
}

func DHKangarooAttack(p, g *big.Int, q, cofactor *big.Int,bob DiffieHellman) *big.Int{
    
    y := new(big.Int).Exp(g,bob.secret_key,p)

    n,r := DHSmallSubgroupAttack(p,cofactor,q,bob)
    
	b := new(big.Int).Div(new(big.Int).Sub(q,big1),r)
    tmp := new(big.Int)

    // y' = y * g^-n
	y_s := new(big.Int).Mod(tmp.Mul(y, tmp.Exp(g, tmp.Neg(n), p)), p)

	// g' = g^r
	g_s := new(big.Int).Exp(g, r, p)

	m := catchKangaroo(p,g_s,y_s,big0,b)
    x := new(big.Int).Add(n,new(big.Int).Mul(r,m))

    return x
}

func InvalidCurveAttack(oracleECDH func(x, y *big.Int) []byte) *big.Int {
	invalidCurves := []elliptic.Curve{elliptic.P128V1(), elliptic.P128V2(), elliptic.P128V3()}

	var modules, remainders []*big.Int

	for _, curve := range invalidCurves {
		factors := Factorize(curve.Params().N, big.NewInt(1<<16))
		
		if factors[0].Cmp(big2) == 0 {
			factors = factors[1:]
		}

		for _, factor := range factors {
			x, y := pickRandomPoint(curve, factor)

			ss := oracleECDH(x, y)

			for k := big.NewInt(1); k.Cmp(factor) <= 0; k.Add(k, big1) {
				ss1 := ecdh(curve, x, y, k.Bytes())

				if hmac.Equal(ss, ss1) && checkDuplicate(remainders, modules, k, factor) {
					remainders = append(remainders, new(big.Int).Set(k))
					modules = append(modules, factor)
					break
				}
			}
		}
	}

	x, _ := Chinese_Remainder_Theorem(remainders, modules)

	return x
}
