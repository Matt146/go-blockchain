/*******************************************************
 * By: TouchPoint Cloud
 * Date (of last edit): 12/26/18
 * Version: v0.0.1
 * Objective: Wallet Library
 * License: [See license.txt]
*******************************************************/

package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

// TODO: I do not need to generate a random string
// as a delimiter for the keys. The keys are stored as base-10 integers

// @TODO: Make checks in order to prevent people from double spending in transactions.
// (REALLY JUST CHECK ENTIRE BLOCKCHAIN TO ADD UP THE SUM OF THE MONEY FOR ONE
// PERSON

const (
	W1DELIMITER           = "`"
	WDELIMITER            = ">"
	TXDELIMITER           = "~"
	WALLET_DELIMITER_LEN  = 20
	RAND_LETTER_SELECTION = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// Transaction - transaction data
type Transaction struct {
	From      string
	To        string
	Delimiter string
	Signature string
	Data      string
	Amount    float64
	Timestamp int64
}

// Wallet - wallet data
type Wallet struct {
	Public  ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

// ScrubTransactionData - This is used to remove all TXDELIMITER's
func ScrubTransactionData(data string) string {
	var revisedBuff string
	for _, _rune := range data {
		if strings.Compare(string(_rune), TXDELIMITER) == 0 {
			revisedBuff += string(_rune)
		}
	}
	return revisedBuff
}

// Serialize - This is used to serialize transaction data.
func (t Transaction) Serialize() string {
	var buff string
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.From)
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.To)
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.Signature)
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.Data)
	buff += TXDELIMITER
	buff += ScrubTransactionData(strconv.FormatFloat(t.Amount, 'f', -1, 64))
	buff += TXDELIMITER
	buff += ScrubTransactionData(strconv.FormatInt(t.Timestamp, 10))
	buff += TXDELIMITER
	return buff
}

// ConvToStr - This is used to convert all of the static transaction
// data into a string that will be used to hash the transaction data.
// EX: The signature and timestamp will not be included
func (t Transaction) ConvToSTR() string {
	var buff string
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.From)
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.To)
	buff += TXDELIMITER
	buff += ScrubTransactionData(t.Data)
	buff += TXDELIMITER
	buff += ScrubTransactionData(strconv.FormatFloat(t.Amount, 'f', -1, 64))
	buff += TXDELIMITER
	return buff
}

// DeserializeTransaction - This is used to deserialize the transaction data.
func DeserializeTransaction(data string) (Transaction, error) {
	t := Transaction{}
	var buff string
	counter := 0
	for _, _rune := range data {
		if string(_rune) == TXDELIMITER {
			switch counter {
			case 1:
				t.From = buff
				buff = ""
			case 2:
				t.To = buff
				buff = ""
			case 3:
				t.Signature = buff
				buff = ""
			case 4:
				t.Data = buff
				buff = ""
			case 5:
				amount, err := strconv.ParseFloat(buff, 64)
				if err != nil {
					return Transaction{}, errors.New("unable to parse float64 for transaction amount")
				}
				t.Amount = amount
			case 6:
				timestamp, err := strconv.ParseInt(buff, 10, 64)
				if err != nil {
					return Transaction{}, errors.New("unable to parse uint64 for timestamp")
				}
				t.Timestamp = timestamp
			}
			buff = ""
			counter++
		} else {
			buff += string(_rune)
		}
	}
	return t, nil
}

// Serialize - This is used to serialize the wallet data.
// This serialized wallet data will be returned in the form
// of a string.
func (w Wallet) Serialize() string {
	var buff string
	buff += w.Private.D.String()
	buff += WDELIMITER
	buff += w.Public.X.String()
	buff += WDELIMITER
	buff += w.Public.Y.String()
	return buff
}

// DeserializeWallet - This is used to deserialize the wallet data.
// This deserialized data will be returned as a Wallet struct.
// If an error occurs, an uninitialized Wallet struct will be returned,
// along with an error. If no error occurs, the error will be nil.
func DeserializeWallet(data string) (Wallet, error) {
	key := strings.Split(data, WDELIMITER)
	// private key
	sk := new(big.Int)
	sk, ok := sk.SetString(key[0], 10)
	if !ok {
		return Wallet{}, errors.New("unable to deserialize wallet")
	}

	// public key X
	pk01 := new(big.Int)
	pk1, ok := pk01.SetString(key[1], 10)
	if !ok {
		return Wallet{}, errors.New("unable to deserialize wallet")
	}

	// public key Y
	pk02 := new(big.Int)
	pk2, ok := pk02.SetString(key[2], 10)
	if !ok {
		return Wallet{}, errors.New("unable to deserialize wallet")
	}
	// BUG here, as we are creating a new ecdsa.PrivateKey struct  and don't know
	// if the curves are randomized
	SKReal := ecdsa.PrivateKey{D: sk, PublicKey: ecdsa.PublicKey{X: pk1, Y: pk2, Curve: elliptic.P256()}}
	w := Wallet{Private: &SKReal, Public: SKReal.PublicKey}
	return w, nil
}

func InitWallet() (Wallet, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Wallet{}, errors.New("unable to generate ecdsa key pair")
	}
	w := Wallet{Private: key, Public: key.PublicKey}
	return w, nil
}

func StoreWallet(file string, w Wallet) error {
	f, err := os.Create(file)
	if err != nil {
		return errors.New("unable to store wallet")
	}
	defer f.Close()
	f.Write([]byte(w.Serialize()))
	return nil
}

func LoadWallet(file string) (Wallet, error) {
	// open the file
	f, err := os.Open(file)
	if err != nil {
		return Wallet{}, errors.New("unable to load wallet")
	}

	// read the file
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return Wallet{}, errors.New("unable to load wallet")
	}

	// deserialize the wallet data
	w, err := DeserializeWallet(string(data[:]))
	if err != nil {
		return Wallet{}, errors.New("unable to load wallet")
	}
	return w, nil
}

func SerializeSignature(r, s *big.Int) string {
	var signatureBuff string
	signatureBuff += r.String()
	signatureBuff += W1DELIMITER
	signatureBuff += s.String()
	return signatureBuff
}

func DeserializeSignature(data string) (*big.Int, *big.Int, error) {
	rs := strings.Split(data, W1DELIMITER)
	r0 := new(big.Int)
	s0 := new(big.Int)

	r, ok := r0.SetString(rs[0], 10)
	if !ok {
		return nil, nil, errors.New("unable to deserialize signature")
	}
	s, ok := s0.SetString(rs[1], 10)
	if !ok {
		return nil, nil, errors.New("unable to deserialize signature")
	}

	return r, s, nil
}

// SerializePubKey
func SerializePubKey(key ecdsa.PublicKey) (string, error) {
	var buff string
	buff += key.X.String()
	buff += W1DELIMITER
	buff += key.Y.String()
	return buff, nil
}

func DeserializePubKey(data string) (ecdsa.PublicKey, error) {
	key := ecdsa.PublicKey{}
	splitStr := strings.Split(data, W1DELIMITER)

	X := new(big.Int)
	X, ok := X.SetString(splitStr[0], 10)
	if !ok {
		return ecdsa.PublicKey{}, errors.New("unable to deserialize public key")
	}

	Y0 := new(big.Int)
	Y, ok := Y0.SetString(splitStr[1], 10)
	if !ok {
		return ecdsa.PublicKey{}, errors.New("unable to deserialize public key")
	}
	key.X = X
	key.Y = Y
	return key, nil
}

func GetTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// Sign - This is used to sign a single transaction with a provided wallet.
func (t Transaction) Sign(w Wallet, to string, amount float64) (string, error) {
	// @TODO below this comment block , please
	// consider to implement serialization of wallet FROM
	// (or the public key) in order to fill in the rest of the
	// transaction data.
	pk := w.Public
	pkStr, err := SerializePubKey(pk)
	if err != nil {
		return "", err
	}
	t.From = pkStr
	t.To = to
	t.Amount = amount
	t.Timestamp = time.Now().UnixNano() / int64(time.Millisecond)

	hash := sha256.Sum256([]byte(t.Serialize()))
	r, s, err := ecdsa.Sign(rand.Reader, w.Private, hash[:])
	if err != nil {
		t.Timestamp = 0
		return "", errors.New("unable to sign transaction")
	}
	signature := SerializeSignature(r, s)
	t.Signature = signature
	return signature, nil
}

func (t Transaction) Verify() (bool, error) {
	hash := sha256.Sum256([]byte(t.Serialize()))
	r, s, err := DeserializeSignature(t.Signature)
	if err != nil {
		return false, errors.New("unable to verify signature due to a signature deserialization error")
	}
	pubKeyDeserialized, err := DeserializePubKey(t.From)
	if err != nil {
		return false, errors.New("unable to verify signature to to a public key deserialization error")
	}
	verify := ecdsa.Verify(&pubKeyDeserialized, []byte(hash[:]), r, s)
	return verify, nil
}

func (w Wallet) Sign(data string) (string, error) {
	hash := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, w.Private, hash[:])
	if err != nil {
		return "", errors.New("unable to sign data using wallet")
	}
	signature := SerializeSignature(r, s)
	return signature, nil
}

func Verify(key ecdsa.PublicKey, data string, signature string) (bool, error) {
	hash := sha256.Sum256([]byte(data))
	r, s, err := DeserializeSignature(signature)
	if err != nil {
		return false, errors.New("unable to verify signature due to a signature deserialization error")
	}
	verify := ecdsa.Verify(&key, []byte(hash[:]), r, s)
	return verify, nil
}
