package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/tuneinsight/lattigo/v4/rlwe"

	paillier "github.com/roasbeef/go-go-gadget-paillier"
	"github.com/tuneinsight/lattigo/v4/bfv"
)

func timeCost(start time.Time){
	tc:=time.Since(start)
	fmt.Printf("time cost = %v\n", tc)
}

type BFV_Scheme struct {
	encoder 	bfv.Encoder
	decryptor bfv.Decryptor
	Pk *rlwe.PublicKey
	encryptorSK bfv.Encryptor
	evaluator bfv.Evaluator
	params bfv.Parameters
}

func (bfv_scheme *BFV_Scheme) BFV_init() {

	// BFV parameters (128 bit security) with plaintext modulus 65929217
	paramDef := bfv.PN13QP218
	paramDef.T = 0x3ee0001
	params, err := bfv.NewParametersFromLiteral(paramDef)
	bfv_scheme.params = params

	if err != nil {
		panic(err)
	}

	bfv_scheme.encoder = bfv.NewEncoder(params)
	kgen := bfv.NewKeyGenerator(params)
	Sk, Pk := kgen.GenKeyPair()
	bfv_scheme.Pk = Pk
	bfv_scheme.decryptor = bfv.NewDecryptor(params, Sk)
	bfv_scheme.encryptorSK = bfv.NewEncryptor(params, Sk)
	bfv_scheme.evaluator = bfv.NewEvaluator(params, rlwe.EvaluationKey{})
}

func testBFV_SIMD() {

	const length = 2048

	nums := make([]int64, 8192) //N = 8192
	new_nums := make([]int64, length)
	var i int64
	for i = 0; i < length; i++ {
		nums[i] = i
	}

	defer timeCost(time.Now())
	var bfv_scheme BFV_Scheme 
	bfv_scheme.BFV_init()

	plaintext := bfv.NewPlaintext(bfv_scheme.params)
	bfv_scheme.encoder.Encode(nums, plaintext)
	cipher := bfv_scheme.encryptorSK.EncryptNew(plaintext)
	bfv_scheme.evaluator.Add(cipher, cipher, cipher)

	decoded_nums := bfv_scheme.encoder.DecodeIntNew(bfv_scheme.decryptor.DecryptNew(cipher))

	for i = 0; i < length; i++ {
		new_nums[i] = decoded_nums[i]
	}

}

func testBFV() {
	const length = 2048

	nums := make([][]int64, length) 
	new_nums := make([]int64, length)
	var i int64
	for i = 0; i < length; i++ {
		nums[i] = make([]int64, 8192)//N = 8192
		nums[i][0] = i
	}

	defer timeCost(time.Now())
	var bfv_scheme BFV_Scheme 
	bfv_scheme.BFV_init()


	plaintexts := make([]*bfv.Plaintext, length)

	for i = 0; i < length; i++ {
		plaintexts[i] = bfv.NewPlaintext(bfv_scheme.params)
		bfv_scheme.encoder.Encode(nums[i], plaintexts[i])
		cipher := bfv_scheme.encryptorSK.EncryptNew(plaintexts[i])
		bfv_scheme.evaluator.Add(cipher, cipher, cipher)
		decoded_nums := bfv_scheme.encoder.DecodeIntNew(bfv_scheme.decryptor.DecryptNew(cipher))
		new_nums[i] = decoded_nums[0]
	}
}

func testPaillier() {
	const length = 2048

	var plaintexts = [length]*big.Int {}
	var new_plaintexts = [length]*big.Int {}
	var i int64
	for i = 0; i < length; i++ {
		plaintexts[i] = new(big.Int).SetInt64(i)
	}

	defer timeCost(time.Now())
	// Generate a private key such that N has 1536 bits
	paillierPrivKey, _ := paillier.GenerateKey(rand.Reader, 1536)

	// Encrypt the numbers and do the homomorphic addition
	var ciphertexts = [length][]byte {}
	var new_ciphers = [length][]byte {}
	for i = 0; i < length; i++ {
		ciphertexts[i], _ = paillier.Encrypt(&paillierPrivKey.PublicKey, plaintexts[i].Bytes())
		new_ciphers[i] = paillier.AddCipher(&paillierPrivKey.PublicKey, ciphertexts[i], ciphertexts[i])
	}
	


	// Decrypt the numbers
	for i = 0; i < length; i++ {
		d, _ := paillier.Decrypt(paillierPrivKey, new_ciphers[i])
		new_plaintexts[i] = new(big.Int).SetBytes(d)
	} 

}

func main() {
	// testPaillier()  //time cost = 23.342696235s
	// testBFV_SIMD()  //time cost = 26.21828ms
	testBFV()          //time cost = 11.386638854s
}