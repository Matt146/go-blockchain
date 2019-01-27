/*******************************************************
 * By: TouchPoint Cloud
 * Date (of last edit): 12/26/18
 * Version: v0.0.1
 * Objective: Blockchain Library
 * License: [See license.txt]
*******************************************************/

package blockchain

import (
	"TouchPoint/wallet"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

const (
	MAX_NONCE            = 18446744073709551614
	MAX_TRANSACTIONS     = 16384            // the most amount of transactions per block
	MAX_BLOCKS           = MAX_TRANSACTIONS // the most amount of blocks per blockchain before another allocation
	ALLOCATION_SIZE      = MAX_BLOCKS       // the amount allocated after MAX_BLOCKS is reached
	MAX_TRANSACTION_ARGS = 7                // the most amount of parameters for a single transaction
	TXDELIMITER          = "~"              // the delimiter for each singular transaction in a block
	BDELIMITER           = "<"              // the delimiter for each element of a singular block
	BCDELIMITER          = "|"              // the delimiter for each singular block in the blockchain
)

// Block - This is the main block struct
type Block struct {
	TX         []wallet.Transaction
	MerkleRoot string
	PrevHash   string
	Difficulty int
	Nonce      uint64
	NonceStr   string
	Timestamp  uint64
}

// Blockchain - This is the main blockchain struct. It is made
// up of a collection of blocks.
type Blockchain struct {
	BS []Block
}

// ScrubBlockData - This is used to remove all BDELIMITER's.
func ScrubBlockData(data string) string {
	var revisedBuff string
	for _, _rune := range data {
		if strings.Compare(string(_rune), BDELIMITER) == 0 {
			revisedBuff += wallet.ScrubTransactionData(string(_rune))
		}
	}
	return revisedBuff
}

// Serialize - This is used to serialize a block.
func (b Block) Serialize() string {
	var buff string
	buff += BDELIMITER
	for _, tx := range b.TX {
		buff += tx.Serialize()
	}
	buff += BDELIMITER
	buff += ScrubBlockData(b.MerkleRoot)
	buff += BDELIMITER
	buff += ScrubBlockData(b.PrevHash)
	buff += BDELIMITER
	buff += ScrubBlockData(fmt.Sprintf("%d", b.Difficulty))
	buff += BDELIMITER
	buff += ScrubBlockData(strconv.FormatUint(b.Nonce, 10))
	buff += BDELIMITER
	buff += ScrubBlockData(b.NonceStr)
	buff += BDELIMITER
	buff += strconv.FormatUint(b.Timestamp, 10)
	buff += BDELIMITER
	return buff
}

func DeserializeBlock(data string) (Block, error) {
	b := Block{}
	var buff string
	var transactionBuff string
	var individualTransactionBuff string
	counter := 0
	transactionCounter := 0
	transactions := make([]wallet.Transaction, 0, MAX_TRANSACTIONS)
	for _, _rune := range data {
		if string(_rune) == BDELIMITER {
			switch counter {
			case 2:
				// deserialize all of the transactions first
				for _, __rune := range transactionBuff {
					if string(__rune) == TXDELIMITER {
						if counter == MAX_TRANSACTION_ARGS+1 {
							t, err := wallet.DeserializeTransaction(individualTransactionBuff)
							if err != nil {
								return Block{}, errors.New("unable to deserialize transaction")
							}
							individualTransactionBuff = ""
							transactions = append(transactions, t)
						}
						transactionCounter++
					} else {
						individualTransactionBuff += string(__rune)
					}
				}
				b.TX = transactions

				// then deserialize the merkle root
				b.MerkleRoot = buff
				buff = ""
			case 3:
				b.PrevHash = buff
				buff = ""
			case 4:
				difficulty, err := strconv.ParseInt(buff, 10, 32)
				if err != nil {
					return Block{}, errors.New("unable to deserialize block difficulty")
				}
				buff = ""
			case 5:
				nonce, err := strconv.ParseUint(buff, 10, 64)
				if err != nil {
					return Block{}, errors.New("unable to deserialize nonce")
				}
				buff = ""
			case 6:
				b.NonceStr = buff
				buff = ""
			case 7:
				timestamp, err := strconv.ParseUint(buff, 10, 64)
				if err != nil {
					return Block{}, errors.New("unable to deserialize timestamp")
				}
				b.Timestamp = timestamp
				buff = ""
			}
			counter++
		} else {
			if counter == 1 {
				transactionBuff += string(_rune)
			} else {
				buff += string(_rune)
			}
		}
	}
	return b, nil
}

func ScrubBlockchainData(data string) string {
	var buff string
	for _, _rune := range data {
		if strings.Compare(string(_rune), BCDELIMITER) != 0 {
			buff += string(_rune)
		}
	}
	return buff
}

func (bc Blockchain) Serialize() string {
	var buff string
	for _, b := range bc.BS {
		buff += BCDELIMITER
		buff += ScrubBlockchainData(b.Serialize())
		buff += BCDELIMITER
	}
	return buff
}

func (bc *Blockchain) Realloc() {
	tempBuff := *bc.BS
	bc.BS = make([]Block, 0, len(bc.BS)+ALLOCATION_SIZE)
	for _, b := range tempBuff {
		bc.BS = append(bc.BS, b)
	}
}

func DeserializeBlockchain(data string) (Blockchain, error) {
	bc := Blockchain{}
	bc.BS = make([]Block, 0, MAX_BLOCKS)
	var blockBuff string
	count := 0
	for _, _rune := range data {
		if strings.Comapre(string(_rune), BCDELIMITER) == 0 {
			count++
			if count != 1 {
				tempBlock, err := DeserializeBlock(blockBuff)
				if err != nil {
					return bc, errors.New("unable to deserialize block")
				}
				if len(bc.BS) == cap(bc.BS) {
					(&bc).Realloc()
				}
				bc.BS = append(bc.BS, tempBlock)
			}
		} else {
			blockBuff += string(_rune)
		}
	}
	return bc
}

func (b *Block) CalcHash() string {
	blockBytes := b.Serialize()
	hash := sha256.Sum256([]byte(blockBytes))
	b.MerkleRoot = string(hash[:])
	return string(hash[:])
}

func (b Block) IsValid() bool {
	// @TODO verify transaction signatures
	curhash := b.MerkleRoot
	b.CalcHash()
	afterhash := b.MerkleRoot
	if strings.Compare(curhash, afterhash) == 0 {
		for x := 0; x < b.Difficulty; x++ {
			if strings.Compare(string(b.MerkleRoot[x]), "0") != 0 {
				return false
			}
		}
		for _, t := range b.TX {
			verify, err := t.Verify()
			if err != nil {
				return false
			}
			if verify == false {
				return false
			}
		}
	} else {
		return false
	}
	return true
}

func (b *Block) Mine() {
	zeroStr := ""
	for b := 0; b < b.Difficulty; b++ {
		zeroStr += "0"
	}
	for {
		if strings.Compare(string(b.MerkleRoot[:b.Difficulty]), zeroStr) == 0 {
			break
		}
		b.CalcHash()
		if b.Nonce >= MAX_NONCE {
			b.NonceStr += "."
			b.Nonce = 0
		} else {
			b.Nonce++
		}
	}
}

func (b *Block) AddToChain(bc *Blockchain) {
	if b.IsValid() == true {
		*b.PrevHash = bc.BS[len(bc)-1].MerkleRoot
		bc.BS = append(bc.BS, *b)
	}
}

func (bc *Blockchain) Save(file string) error {
	f, err := os.Create(file)
	defer f.Close()
	if err != nil {
		return errors.New("unable to create file to write blockchain to")
	}
	bcSerialized := (*bc).Serialize()
	f.Write([]byte(bcSerialized))
}

func LoadBlockchain(file string) (*Blockchain, error) {
	f, err := os.Open(file)
	if err != nil {
		return &Blockchain{}, errors.New("unable to open file to read blockchain data from")
	}
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return &Blockchain{}, errors.New("unable to read blockchain data")
	}
	blockchainStr := string(bytes[:])
	bc, err := DeserializeBlockchain(blockchainStr)
	if err != nil {
		return &Blockchain{}, errors.New("unable to deserialize blockchain data!")
	}
	return &bc, nil
}
