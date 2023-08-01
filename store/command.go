package store

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/catalogfi/indexer/command"
	"github.com/catalogfi/indexer/model"
	"gorm.io/gorm"
)

func (s *storage) GetPreviousBlockHeight(blockhash string) (int32, error) {
	block := model.Block{}
	if res := s.db.First(&block, "hash = ?", blockhash); res.Error != nil {
		return 0, res.Error
	}
	return block.Height, nil
}

func (s *storage) GetLatestBlockHeight() (int32, error) {
	block := &model.Block{}
	if resp := s.db.Order("height desc").First(block); resp.Error != nil {
		if resp.Error == gorm.ErrRecordNotFound {
			return -1, nil
		}
		return -1, resp.Error
	}
	return block.Height, nil
}
func (s *storage) GetLatestUnorphanBlockHeight() (int32, error) {
	block := &model.Block{}
	if resp := s.db.Where("is_orphan = ?", false).Order("height desc").First(block); resp.Error != nil {
		if resp.Error == gorm.ErrRecordNotFound {
			return -1, nil
		}
		return -1, resp.Error
	}
	return block.Height, nil
}

func (s *storage) GetBlockHash(height int32) (string, error) {
	block := &model.Block{}
	if resp := s.db.First(block, "height = ?", height); resp.Error != nil {
		return "", resp.Error
	}
	return block.Hash, nil
}

func (s *storage) GetLatestBlockHash() (string, error) {
	block := &model.Block{}
	if resp := s.db.Order("height desc").First(block); resp.Error != nil {
		return "", resp.Error
	}
	return block.Hash, nil
}

func (s *storage) GetRawMempoolFunc() ([]string, error) {
	// txn := &model.Transaction{}
	count := int32(0)
	// res := s.db.Where("block_hash IS NULL").Count(&count)
	txs := []model.Transaction{}
	if resp := s.db.Order("block_index").Find(&txs, "block_hash = ?", ""); resp.Error != nil {
		return nil, resp.Error
	}
	println("transaction hash:")
	txsArray := []string{}
	count = int32(len(txs))
	for i := 0; i < len(txs); i++ {
		// println(txs[i].Hash)
		if txs[i].Hash != "0000000000000000000000000000000000000000000000000000000000000000" {
			txsArray = append(txsArray, txs[i].Hash)
		}
	}
	println(count)
	return txsArray, nil
}

func GetBlockByHeight(height int32, db *gorm.DB) (*model.Block, error) {
	block := &model.Block{}
	resp := db.First(block, "height = ?", height)
	return block, resp.Error
}

func (s *storage) VerifyChainFunc() (bool, error) {

	height, err := s.GetLatestUnorphanBlockHeight()
	if err != nil {
		println("err")
		return false, err
	}
	block, err := GetBlockByHeight(height, s.db)
	if err != nil {
		println("error")
		return false, err
	}
	for {
		prevBlock := &model.Block{}
		println("block height: ", block.Height)
		if block.Height == 0 {
			return true, nil
		}
		resp := s.db.First(prevBlock, "hash = ?", block.PreviousBlock)
		if resp.Error != nil {
			// println("error")
			// println("block.PreviousBlock: ", block.PreviousBlock)
			// println("block.Height: ", block.Height)
			// println("prevBlock.Height: ", prevBlock.Height)
			// println("prevBlock.Hash: ", prevBlock.Hash)
			return false, resp.Error
		}
		// println("block.PreviousBlock: ", block.PreviousBlock)
		// println("block.Height: ", block.Height)
		// println("prevBlock.Height: ", prevBlock.Height)
		// println("prevBlock.Hash: ", prevBlock.Hash)
		if prevBlock.Height != block.Height-1 {
			// println("error")
			// println("block.Height - 1: ", block.Height-1)
			// println("tempBlock.Height: ", prevBlock.Height)
			return false, nil
		}
		block = prevBlock
		// println("block height: ", block.Height)
	}
}

func (s *storage) CalculateDifficulty() (float64, error) {
	blockHash := "3a1b2a9bbd221ce2cf8241d11038de147e023a32bb5f3ddb86383600a6275686"
	header, err := s.GetHeaderFromHash(blockHash)
	if err != nil {
		return 0, err
	}
	bits := header.Header.Bits
	bitBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bitBytes, bits)
	difficultyDen := new(big.Int).Lsh(new(big.Int).SetBytes(bitBytes[1:]), 8*uint(bitBytes[0]-3))
	difficultyNum, ok := new(big.Int).SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)
	if !ok {
		panic("failed to parse difficulty denominator")
	}
	ratio, _ := new(big.Float).Quo(new(big.Float).SetInt(difficultyNum), new(big.Float).SetInt(difficultyDen)).Float64()
	return ratio, nil
}
func (s *storage) GetBlockCount() (int32, error) {
	return s.GetLatestBlockHeight()
}

func (s *storage) GetNormalBlockFromHash(blockHash string) (*model.Block, error) {
	block := &model.Block{}
	if resp := s.db.First(block, "hash = ?", blockHash); resp.Error != nil {
		return nil, resp.Error
	}
	return block, nil
}

func (s *storage) GetBlockFromHash(blockHash string) (*btcutil.Block, error) {
	//gets the block
	block := &model.Block{}
	if resp := s.db.First(block, "hash = ?", blockHash); resp.Error != nil {
		return nil, resp.Error
	}
	//get the prev block hash
	prevHash, err := chainhash.NewHashFromStr(block.PreviousBlock)
	if err != nil {
		return nil, err
	}
	//get the merkle root hash
	merkleRootHash, err := chainhash.NewHashFromStr(block.MerkleRoot)
	if err != nil {
		return nil, err
	}

	blockHeader := wire.NewBlockHeader(block.Version, prevHash, merkleRootHash, block.Bits, block.Nonce)
	blockHeader.Timestamp = block.Timestamp

	msgBlock := wire.NewMsgBlock(blockHeader)

	txs := []model.Transaction{}
	if resp := s.db.Order("block_index").Find(&txs, "block_hash = ?", blockHash); resp.Error != nil {
		return nil, resp.Error
	}
	for _, transaction := range txs {
		tx := wire.NewMsgTx(transaction.Version)
		tx.LockTime = transaction.LockTime
		if err := s.addInputsAndOutputs(transaction.Hash, tx); err != nil {
			return nil, err
		}
		if err := msgBlock.AddTransaction(tx); err != nil {
			return nil, err
		}
	}

	b := btcutil.NewBlock(msgBlock)
	b.SetHeight(block.Height)
	return b, nil
}

func (s *storage) GetHeaderFromHash(blockHash string) (command.BlockHeader, error) {
	block := &model.Block{}
	if resp := s.db.First(block, "hash = ?", blockHash); resp.Error != nil {
		return command.BlockHeader{}, resp.Error
	}
	prevHash, err := chainhash.NewHashFromStr(block.PreviousBlock)
	if err != nil {
		return command.BlockHeader{}, err
	}
	merkleRootHash, err := chainhash.NewHashFromStr(block.MerkleRoot)
	if err != nil {
		return command.BlockHeader{}, err
	}
	blockHeader := wire.NewBlockHeader(block.Version, prevHash, merkleRootHash, block.Bits, block.Nonce)
	blockHeader.Timestamp = block.Timestamp

	var result int64
	if err := s.db.Model(&model.Transaction{}).Where("block_hash = ?", block.Hash).Count(&result).Error; err != nil {
		return command.BlockHeader{}, err
	}

	return command.BlockHeader{
		Header: blockHeader,
		Height: block.Height,
		NumTxs: result,
	}, nil
}

func (s *storage) GetHeaderFromHeight(height int32) (command.BlockHeader, error) {
	block := &model.Block{}
	if resp := s.db.First(block, "height = ?", height); resp.Error != nil {
		return command.BlockHeader{}, resp.Error
	}
	prevHash, err := chainhash.NewHashFromStr(block.PreviousBlock)
	if err != nil {
		return command.BlockHeader{}, err
	}
	merkleRootHash, err := chainhash.NewHashFromStr(block.MerkleRoot)
	if err != nil {
		return command.BlockHeader{}, err
	}
	blockHeader := wire.NewBlockHeader(block.Version, prevHash, merkleRootHash, block.Bits, block.Nonce)
	blockHeader.Timestamp = block.Timestamp

	var result int64
	if err := s.db.Model(&model.Transaction{}).Where("block_hash = ?", block.Hash).Count(&result).Error; err != nil {
		return command.BlockHeader{}, err
	}

	return command.BlockHeader{
		Header: blockHeader,
		Height: block.Height,
		NumTxs: result,
	}, nil
}

func (s *storage) addInputsAndOutputs(txHash string, tx *wire.MsgTx) error {
	txIns := []model.OutPoint{}
	txOuts := []model.OutPoint{}
	if res := s.db.Order("spending_tx_index").Find(&txIns, "spending_tx_hash = ?", txHash); res.Error != nil {
		return res.Error
	}
	for _, txIn := range txIns {
		opHash, err := chainhash.NewHashFromStr(txIn.FundingTxHash)
		if err != nil {
			return fmt.Errorf("invalid op hash: %v", err)
		}

		signatureScript, err := hex.DecodeString(txIn.SignatureScript)
		if err != nil {
			return fmt.Errorf("failed to decode sig script: %v", err)
		}

		witness := strings.Split(txIn.Witness, ",")
		witnessBytes := make([][]byte, len(witness))
		for i := range witness {
			witness, err := hex.DecodeString(witness[i])
			if err != nil {
				return err
			}
			witnessBytes[i] = make([]byte, 32)
			copy(witnessBytes[i], witness)
		}

		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(opHash, txIn.FundingTxIndex), signatureScript, witnessBytes))
	}

	if res := s.db.Order("funding_tx_index").Find(&txOuts, "funding_tx_hash = ?", txHash); res.Error != nil {
		return res.Error
	}
	for _, txOut := range txOuts {
		pkScript, err := hex.DecodeString(txOut.PkScript)
		if err != nil {
			return fmt.Errorf("failed to decode pkScript: %v", err)
		}

		tx.AddTxOut(wire.NewTxOut(txOut.Value, pkScript))
	}
	return nil
}

func (s *storage) GetTransaction(txHash string) (command.Transaction, error) {
	transaction := model.Transaction{}
	if res := s.db.Joins("Block").First(&transaction, "transactions.hash = ?", txHash); res.Error != nil {
		return command.Transaction{}, res.Error
	}
	tx := wire.NewMsgTx(transaction.Version)
	tx.LockTime = transaction.LockTime
	if err := s.addInputsAndOutputs(txHash, tx); err != nil {
		return command.Transaction{}, err
	}

	if transaction.Block == nil {
		return command.Transaction{
			Tx: tx,
		}, nil
	}
	return command.Transaction{
		Tx:        tx,
		BlockHash: transaction.BlockHash,
		Height:    transaction.Block.Height,
		BlockTime: transaction.Block.Timestamp.Unix(),
	}, nil
}

func (storage *storage) ListUnspent(startBlock, endBlock int, addresses []string, includeUnsafe bool, options command.ListUnspentQueryOptions) ([]model.OutPoint, error) {
	outpoints := []model.OutPoint{}
	if !includeUnsafe {
		resp := storage.db.Joins("FundingTx.Block", "height >= ? AND height <= ?", startBlock, endBlock).Joins("FundingTx", "safe = ?", true).Limit(int(options.MaximumCount)).Find(&outpoints, "spender IN ? AND value >= ? AND value <= ?", addresses, options.MinimumAmount, options.MaximumAmount)
		return outpoints, resp.Error
	}
	resp := storage.db.Joins("FundingTx.Block", "height >= ? AND height <= ?", startBlock, endBlock).Joins("FundingTx").Limit(int(options.MaximumCount)).Find(&outpoints, "spender IN ? AND value >= ? AND value <= ?", addresses, options.MinimumAmount, options.MaximumAmount)
	return outpoints, resp.Error
}
