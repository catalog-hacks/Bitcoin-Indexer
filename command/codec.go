package command

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/catalogfi/indexer/model"
)

// getblockheader
type VerboseBlockHeader struct {
	Hash                 string  `json:"hash"`
	Confirmations        uint32  `json:"confirmations"`
	Height               int32   `json:"height"`
	Version              int32   `json:"version"`
	VersionHex           string  `json:"versionHex"`
	MerkleRoot           string  `json:"merkleroot"`
	Time                 int64   `json:"time"`
	MedianTime           int64   `json:"mediantime"`
	Nonce                uint32  `json:"nonce"`
	Bits                 string  `json:"bits"`
	Difficulty           float64 `json:"difficulty"`
	NumberOfTransactions int64   `json:"nTx"`
	PreviousBlockHash    string  `json:"previousblockhash"`
	NextBlockHash        string  `json:"nextblockhash,omitempty"`
}

func calculateDifficulty(bits uint32) float64 {
	bitBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bitBytes, bits)
	difficultyDen := new(big.Int).Lsh(new(big.Int).SetBytes(bitBytes[1:]), 8*uint(bitBytes[0]-3))
	difficultyNum, ok := new(big.Int).SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)
	if !ok {
		panic("failed to parse difficulty denominator")
	}
	ratio, _ := new(big.Float).Quo(new(big.Float).SetInt(difficultyNum), new(big.Float).SetInt(difficultyDen)).Float64()
	return ratio
}

func EncodeBlockHeader(block *wire.BlockHeader, numTxs int64, height int32, confirmations uint32, medianTime int64, nextBlockHash string) (VerboseBlockHeader, error) {
	return VerboseBlockHeader{
		Hash:                 block.BlockHash().String(),
		Confirmations:        confirmations,
		Height:               height,
		Version:              block.Version,
		VersionHex:           strconv.FormatInt(int64(block.Version), 16),
		MerkleRoot:           block.MerkleRoot.String(),
		Time:                 block.Timestamp.Unix(),
		MedianTime:           medianTime,
		Bits:                 strconv.FormatInt(int64(block.Bits), 16),
		Nonce:                block.Nonce,
		Difficulty:           calculateDifficulty(block.Bits),
		NumberOfTransactions: numTxs,
		PreviousBlockHash:    block.PrevBlock.String(),
		NextBlockHash:        nextBlockHash,
	}, nil
}

// getblock
type VerboseBlock struct {
	Hash                 string      `json:"hash"`
	Confirmations        uint32      `json:"confirmations"`
	Height               int32       `json:"height"`
	Version              int32       `json:"version"`
	VersionHex           string      `json:"versionHex"`
	MerkleRoot           string      `json:"merkleroot"`
	Time                 int64       `json:"time"`
	MedianTime           int64       `json:"mediantime"`
	Nonce                uint32      `json:"nonce"`
	Bits                 string      `json:"bits"`
	Difficulty           float64     `json:"difficulty"`
	NumberOfTransactions int         `json:"nTx"`
	PreviousBlockHash    string      `json:"previousblockhash"`
	NextBlockHash        string      `json:"nextblockhash,omitempty"`
	StrippedSize         int         `json:"strippedsize"`
	Size                 int         `json:"size"`
	Weight               int         `json:"weight"`
	Transactions         interface{} `json:"tx"`
}

func EncodeBlock(block *btcutil.Block, confirmations uint32, medianTime int64, nextBlockHash string, verbose int) (VerboseBlock, error) {
	return VerboseBlock{
		Hash:                 block.Hash().String(),
		Confirmations:        confirmations,
		Size:                 block.MsgBlock().SerializeSize(),
		StrippedSize:         block.MsgBlock().SerializeSizeStripped(),
		Weight:               3*block.MsgBlock().SerializeSizeStripped() + block.MsgBlock().SerializeSize(),
		Height:               block.Height(),
		Version:              block.MsgBlock().Header.Version,
		VersionHex:           strconv.FormatInt(int64(block.MsgBlock().Header.Version), 16),
		MerkleRoot:           block.MsgBlock().Header.MerkleRoot.String(),
		Transactions:         getTxs(block, confirmations, verbose),
		Time:                 block.MsgBlock().Header.Timestamp.Unix(),
		MedianTime:           medianTime,
		Bits:                 strconv.FormatInt(int64(block.MsgBlock().Header.Bits), 16),
		Nonce:                block.MsgBlock().Header.Nonce,
		Difficulty:           calculateDifficulty(block.MsgBlock().Header.Bits),
		NumberOfTransactions: len(block.Transactions()),
		PreviousBlockHash:    block.MsgBlock().Header.PrevBlock.String(),
		NextBlockHash:        nextBlockHash,
	}, nil
}

func getTxs(block *btcutil.Block, confirmations uint32, verbose int) interface{} {
	txs := make([]interface{}, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		if verbose == 1 {
			txs[i] = tx.Hash().String()
		} else {
			txs[i] = EncodeTransaction(tx.MsgTx(), block.Hash().String(), confirmations, block.MsgBlock().Header.Timestamp.Unix())
		}
	}
	return txs
}

// getrawtransaction
type VerboseTransaction struct {
	Hex           string       `json:"hex"`
	TxID          string       `json:"txid"`
	Hash          string       `json:"hash"`
	Size          int          `json:"size"`
	VSize         int          `json:"vsize"`
	Weight        int          `json:"weight"`
	Version       int32        `json:"version"`
	LockTime      uint32       `json:"locktime"`
	VINs          interface{}  `json:"vin"`
	VOUTs         []VerboseOut `json:"vout"`
	BlockHash     string       `json:"blockhash"`
	Confirmations uint32       `json:"confirmations"`
	BlockTime     int64        `json:"blocktime"`
	Time          int64        `json:"time"`
}

type VerboseIn struct {
	TxID        string          `json:"txid"`
	Vout        uint32          `json:"vout"`
	ScriptSig   ScriptSignature `json:"scriptSig"`
	Sequence    uint32          `json:"sequence"`
	TxInWitness []string        `json:"txinwitness"`
}

type Coinbase struct {
	Coinbase    string   `json:"coinbase"`
	TxInWitness []string `json:"txinwitness"`
	Sequence    uint32   `json:"sequence"`
}

type VerboseOut struct {
	Value        float64      `json:"value"`
	Index        uint32       `json:"n"`
	ScriptPubKey ScriptPubKey `json:"scriptPubKey"`
}

type ScriptSignature struct {
	ASM string `json:"asm"`
	HEX string `json:"hex"`
}

type ScriptPubKey struct {
	ASM     string `json:"asm"`
	HEX     string `json:"hex"`
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
}

func EncodeTransaction(tx *wire.MsgTx, blockHash string, confirmations uint32, time int64) VerboseTransaction {
	buf := new(bytes.Buffer)
	if err := tx.Serialize(buf); err != nil {
		panic(err)
	}
	weight := 3*tx.SerializeSizeStripped() + tx.SerializeSize()
	vsize := int(math.Ceil(float64(weight) / float64(4)))
	println("vsize", vsize)
	return VerboseTransaction{
		Hex:           hex.EncodeToString(buf.Bytes()),
		TxID:          tx.TxHash().String(),
		Hash:          tx.WitnessHash().String(),
		Size:          tx.SerializeSize(),
		VSize:         vsize,
		Weight:        weight,
		VINs:          EncodeVINs(tx.TxIn),
		VOUTs:         EncodeVOUTs(tx.TxOut),
		Version:       tx.Version,
		LockTime:      tx.LockTime,
		BlockHash:     blockHash,
		Confirmations: confirmations,
		Time:          time,
		BlockTime:     time,
	}
}

func EncodeVINs(txins []*wire.TxIn) interface{} {
	if len(txins) == 1 {
		vin := txins[0]
		if vin.PreviousOutPoint.Index == 4294967295 {
			witness := make([]string, len(vin.Witness))
			for j, w := range vin.Witness {
				witness[j] = hex.EncodeToString(w)
			}
			return []Coinbase{{
				Coinbase:    hex.EncodeToString(vin.SignatureScript),
				TxInWitness: witness,
				Sequence:    vin.Sequence,
			}}
		}
	}

	vins := make([]VerboseIn, len(txins))
	for i, vin := range txins {
		witness := make([]string, len(vin.Witness))
		for j, w := range vin.Witness {
			witness[j] = hex.EncodeToString(w)
		}

		asm, err := txscript.DisasmString(vin.SignatureScript)
		if err != nil {
			fmt.Println(err)
		}

		vins[i] = VerboseIn{
			TxID: vin.PreviousOutPoint.Hash.String(),
			Vout: vin.PreviousOutPoint.Index,
			ScriptSig: ScriptSignature{
				ASM: asm,
				HEX: hex.EncodeToString(vin.SignatureScript),
			},
			Sequence:    vin.Sequence,
			TxInWitness: witness,
		}
	}
	return vins
}

func EncodeVOUTs(txouts []*wire.TxOut) []VerboseOut {
	vouts := make([]VerboseOut, len(txouts))
	for i, vout := range txouts {
		asm, err := txscript.DisasmString(vout.PkScript)
		if err != nil {
			panic(err)
		}

		vouts[i] = VerboseOut{
			Value: float64(vout.Value) / float64(100000000),
			Index: uint32(i),
			ScriptPubKey: ScriptPubKey{
				ASM:  asm,
				HEX:  hex.EncodeToString(vout.PkScript),
				Type: "nulldata",
			},
		}

		pks, err := txscript.ParsePkScript(vout.PkScript)
		if err == nil {
			addr, err := pks.Address(&chaincfg.RegressionNetParams)
			if err != nil {
				panic(err)
			}
			vouts[i].ScriptPubKey.Address = addr.EncodeAddress()
			vouts[i].ScriptPubKey.Type = pks.Class().String()
		}
	}
	return vouts
}

// listunspent
type ListUnspentQueryOptionsReq struct {
	MinimumAmount    interface{} `json:"minimumAmount"`
	MaximumAmount    interface{} `json:"maximumAmount"`
	MaximumCount     interface{} `json:"maximumCount"`
	MinimumSumAmount interface{} `json:"minimumSumAmount"`
}

type ListUnspentQueryOptions struct {
	MinimumAmount    int64
	MaximumAmount    int64
	MaximumCount     uint32
	MinimumSumAmount int64
}

type Unspent struct {
	TxID          string  `json:"txid"`
	Vout          uint32  `json:"vout"`
	Address       string  `json:"address"`
	Label         string  `json:"label"`
	Amount        float64 `json:"amount"`
	ScriptPubKey  string  `json:"scriptPubKey"`
	WitnessScript string  `json:"witnessScript"`
	Spendable     bool    `json:"spendable"`
	Solvable      bool    `json:"solvable"`
	Reused        bool    `json:"reused"`
	Description   string  `json:"desc"`
	Confirmations uint32  `json:"confirmations"`
	Safe          bool    `json:"safe"`
}

func EncodeUnspent(op model.OutPoint, tip int32) Unspent {
	return Unspent{
		TxID:          op.FundingTxHash,
		Vout:          op.FundingTxIndex,
		Address:       op.Spender,
		Label:         "",
		Amount:        float64(op.Value) / float64(100000000),
		ScriptPubKey:  op.PkScript,
		WitnessScript: op.Witness,
		Confirmations: uint32(tip-op.FundingTx.Block.Height) + 1,
	}
}

// getmempoolinfo
type GetMempoolInfoData struct {
	Loaded           bool    `json:"loaded"`
	Size             int     `json:"size"`
	Bytes            int     `json:"bytes"`
	Usage            int     `json:"usage"`
	TotalFee         float64 `json:"total_fee"`
	MaxMempool       int     `json:"maxmempool"`
	MempoolMinFee    float64 `json:"mempoolminfee"`
	MinRelayTxFee    float64 `json:"minrelaytxfee"`
	UnbroadcastCount int     `json:"unbroadcastcount"`
}

func EncodeMempoolInfo(rawMempool []string) (GetMempoolInfoData, error) {
	bytes := len(rawMempool) * 208
	mempoolOverflow := 300000000 - len(rawMempool)
	loaded := true
	if mempoolOverflow < 0 {
		loaded = false
	}
	//other reasons of loaded being false is Bitcoin Core Node Not Fully Synced
	return GetMempoolInfoData{
		Loaded:   loaded, //when is this false?
		Size:     len(rawMempool),
		Bytes:    bytes, //how to calc the bytes?
		Usage:    6624,  //how to calc the usage?
		TotalFee: float64(bytes) / 100000000.0,
		// TotalFee:         0.00000839,
		MaxMempool:       300000000,
		MempoolMinFee:    0.00001000,
		MinRelayTxFee:    0.00001000,
		UnbroadcastCount: len(rawMempool), //it is different when the mempool is broadcasted in parts.
	}, nil
}

type MempoolEntryData struct {
	Fees struct {
		Base       float64 `json:"base"`
		Modified   float64 `json:"modified"`
		Ancestor   float64 `json:"ancestor"`
		Descendant float64 `json:"descendant"`
	} `json:"fees"`
	VSize             int      `json:"vsize"`
	Weight            int      `json:"weight"`
	Fee               float64  `json:"fee"`
	ModifiedFee       float64  `json:"modifiedfee"`
	Time              int      `json:"time"`
	Height            int      `json:"height"`
	DescendantCount   int      `json:"descendantcount"`
	DescendantSize    int      `json:"descendantsize"`
	DescendantFees    int      `json:"descendantfees"`
	AncestorCount     int      `json:"ancestorcount"`
	AncestorSize      int      `json:"ancestorsize"`
	AncestorFees      int      `json:"ancestorfees"`
	WTXID             string   `json:"wtxid"`
	Depends           []string `json:"depends"`
	SpentBy           []string `json:"spentby"`
	BIP125Replaceable bool     `json:"bip125-replaceable"`
	Unbroadcast       bool     `json:"unbroadcast"`
}

func EncodeMempoolEntry(height int) (MempoolEntryData, error) {
	info := MempoolEntryData{
		Fees: struct {
			Base       float64 `json:"base"`
			Modified   float64 `json:"modified"`
			Ancestor   float64 `json:"ancestor"`
			Descendant float64 `json:"descendant"`
		}{Base: 0.00000208, Modified: 0.00000208, Ancestor: 0.00000208, Descendant: 0.00000208},
		VSize:             208,
		Weight:            832,
		Fee:               0.00000208,
		ModifiedFee:       0.00000208,
		Time:              1688985178,
		Height:            height,
		DescendantCount:   1,
		DescendantSize:    208,
		DescendantFees:    208,
		AncestorCount:     1,
		AncestorSize:      208,
		AncestorFees:      208,
		WTXID:             "0741ec8ed1622bb3e060c94b7027efafbbf2ffb7149f40b67526b52d856c582e",
		Depends:           []string{},
		SpentBy:           []string{},
		BIP125Replaceable: false,
		Unbroadcast:       false,
	}
	return info, nil
}

type BlockStatsData struct {
	AvgFee             int    `json:"avgfee"`
	AvgFeeRate         int    `json:"avgfeerate"`
	AvgTxSize          int    `json:"avgtxsize"`
	BlockHash          string `json:"blockhash"`
	FeeRatePercentiles []int  `json:"feerate_percentiles"`
	Height             int    `json:"height"`
	Ins                int    `json:"ins"`
	MaxFee             int    `json:"maxfee"`
	MaxFeeRate         int    `json:"maxfeerate"`
	MaxTxSize          int    `json:"maxtxsize"`
	MedianFee          int    `json:"medianfee"`
	MedianTime         int64  `json:"mediantime"`
	MedianTxSize       int    `json:"mediantxsize"`
	MinFee             int    `json:"minfee"`
	MinFeeRate         int    `json:"minfeerate"`
	MinTxSize          int    `json:"mintxsize"`
	Outs               int    `json:"outs"`
	Subsidy            int    `json:"subsidy"`
	SWTotalSize        int    `json:"swtotal_size"`
	SWTotalWeight      int    `json:"swtotal_weight"`
	SWTxs              int    `json:"swtxs"`
	Time               int64  `json:"time"`
	TotalOut           int    `json:"total_out"`
	TotalSize          int    `json:"total_size"`
	TotalWeight        int    `json:"total_weight"`
	TotalFee           int    `json:"totalfee"`
	Txs                int    `json:"txs"`
	UtxoIncrease       int    `json:"utxo_increase"`
	UtxoSizeInc        int    `json:"utxo_size_inc"`
}

func EncodeBlockStatsData(block *btcutil.Block, hash string, height int, medianTime int64) (BlockStatsData, error) {
	stats := BlockStatsData{
		AvgFee:             0,
		AvgFeeRate:         0,
		AvgTxSize:          0,
		BlockHash:          hash,
		FeeRatePercentiles: []int{0, 0, 0, 0, 0},
		Height:             height,
		Ins:                0,
		MaxFee:             0,
		MaxFeeRate:         0,
		MaxTxSize:          0,
		MedianFee:          0,
		MedianTime:         medianTime,
		MedianTxSize:       0,
		MinFee:             0,
		MinFeeRate:         0,
		MinTxSize:          0,
		Outs:               2,
		Subsidy:            5000000000,
		SWTotalSize:        0,
		SWTotalWeight:      0,
		SWTxs:              0,
		Time:               block.MsgBlock().Header.Timestamp.Unix(),
		TotalOut:           0,
		TotalSize:          0,
		TotalWeight:        0,
		TotalFee:           0,
		Txs:                len(block.Transactions()),
		UtxoIncrease:       2,
		UtxoSizeInc:        160,
	}
	return stats, nil
}

// getchaintips
type ChainTipsData struct {
	Height    int    `json:"height"`
	Hash      string `json:"hash"`
	BranchLen int    `json:"branchlen"`
	Status    string `json:"status"`
}

func EncodeChainTipsData() ([]ChainTipsData, error) {
	chaintipsarr := []ChainTipsData{
		{Height: 378, Hash: "4af358ce9cdc62a40e22254187a5aaeb56179a7031b1bda6b401aea0ef8c266d", BranchLen: 229, Status: "invalid"},
		{Height: 376, Hash: "653db6033f01833e2c5ae7effb9f5c0033f2b64df670094b3bbe7b17b0aeed30", BranchLen: 227, Status: "invalid"},
		{Height: 338, Hash: "7f1c3d91b2004273b4e7ff659db4299b6119a8b14bdd65a01f26561a8bd1e2ff", BranchLen: 189, Status: "invalid"},
		{Height: 326, Hash: "26a113ebccb60b462742f37c501efa769073e673c45cb06d56ddb88ef3c9cd08", BranchLen: 177, Status: "invalid"},
		{Height: 326, Hash: "67f91b91019fd878b64937c13fd3ad50dded1e8b341a71a7745a86410217964b", BranchLen: 177, Status: "invalid"},
		{Height: 324, Hash: "42bde9d7999b1bbf48e50359fa8d3b1d816a2b4e494cec9eb70baed9b5789d3f", BranchLen: 175, Status: "invalid"},
		{Height: 191, Hash: "7d9f1eb0af677737302f90bf1ed381d8773e91f68d174b3a32817ce1571c70e7", BranchLen: 0, Status: "active"},
		{Height: 10, Hash: "340905cc4fe9390191ef266bde3174a166fc95b58d91da10372aa52730cab0d5", BranchLen: 10, Status: "headers-only"},
	}
	return chaintipsarr, nil
}

// getblockchaininfo
type SoftFork struct {
	Type   string `json:"type"`
	Active bool   `json:"active"`
	Height int    `json:"height,omitempty"`
	BIP9   struct {
		Status     string `json:"status"`
		StartTime  int    `json:"start_time,omitempty"`
		Timeout    int    `json:"timeout,omitempty"`
		Since      int    `json:"since,omitempty"`
		Statistics struct {
			Period    int  `json:"period"`
			Threshold int  `json:"threshold"`
			Elapsed   int  `json:"elapsed"`
			Count     int  `json:"count"`
			Possible  bool `json:"possible"`
		} `json:"statistics,omitempty"`
		MinActivationHeight int `json:"min_activation_height,omitempty"`
	} `json:"bip9,omitempty"`
}

type BlockChainInfoData struct {
	Chain                string              `json:"chain"`
	Blocks               int                 `json:"blocks"`
	Headers              int                 `json:"headers"`
	BestBlockHash        string              `json:"bestblockhash"`
	Difficulty           float64             `json:"difficulty"`
	MedianTime           int                 `json:"mediantime"`
	VerificationProgress float64             `json:"verificationprogress"`
	InitialBlockDownload bool                `json:"initialblockdownload"`
	Chainwork            string              `json:"chainwork"`
	SizeOnDisk           int                 `json:"size_on_disk"`
	Pruned               bool                `json:"pruned"`
	SoftForks            map[string]SoftFork `json:"softforks"`
	Warnings             string              `json:"warnings"`
}
type statistics struct {
	Period    int  `json:"period"`
	Threshold int  `json:"threshold"`
	Elapsed   int  `json:"elapsed"`
	Count     int  `json:"count"`
	Possible  bool `json:"possible"`
}

func EncodeGetBlockChainInfo(bestblockhash string, blockcount int, headercount int, difficulty float64, medianTime int64) (BlockChainInfoData, error) {
	info := BlockChainInfoData{
		Chain:                "main",
		Blocks:               blockcount,
		Headers:              headercount,
		BestBlockHash:        bestblockhash,
		Difficulty:           difficulty,
		MedianTime:           int(medianTime),
		VerificationProgress: 1,
		InitialBlockDownload: true,
		Chainwork:            "0000000000000000000000000000000000000000000000000000000000000180",
		SizeOnDisk:           147269,
		Pruned:               false,
		SoftForks: map[string]SoftFork{
			"bip34": {
				Type:   "buried",
				Active: false,
				Height: 500,
			},
			"bip66": {
				Type:   "buried",
				Active: false,
				Height: 1251,
			},
			"bip65": {
				Type:   "buried",
				Active: false,
				Height: 1351,
			},
			"csv": {
				Type:   "buried",
				Active: false,
				Height: 432,
			},
			"segwit": {
				Type:   "buried",
				Active: true,
				Height: 0,
			},
			"testdummy": {
				Type: "bip9",
				BIP9: struct {
					Status     string `json:"status"`
					StartTime  int    `json:"start_time,omitempty"`
					Timeout    int    `json:"timeout,omitempty"`
					Since      int    `json:"since,omitempty"`
					Statistics struct {
						Period    int  `json:"period"`
						Threshold int  `json:"threshold"`
						Elapsed   int  `json:"elapsed"`
						Count     int  `json:"count"`
						Possible  bool `json:"possible"`
					} `json:"statistics,omitempty"`
					MinActivationHeight int `json:"min_activation_height,omitempty"`
				}{
					Status:     "started",
					StartTime:  0,
					Timeout:    9223372036854775807,
					Since:      144,
					Statistics: statistics{432, 432, 0, 0, false},
				},
				Active: false,
			},
			"taproot": {
				Type: "bip9",
				BIP9: struct {
					Status     string `json:"status"`
					StartTime  int    `json:"start_time,omitempty"`
					Timeout    int    `json:"timeout,omitempty"`
					Since      int    `json:"since,omitempty"`
					Statistics struct {
						Period    int  `json:"period"`
						Threshold int  `json:"threshold"`
						Elapsed   int  `json:"elapsed"`
						Count     int  `json:"count"`
						Possible  bool `json:"possible"`
					} `json:"statistics,omitempty"`
					MinActivationHeight int `json:"min_activation_height,omitempty"`
				}{
					Status:              "active",
					StartTime:           -1,
					Timeout:             9223372036854775807,
					Since:               0,
					MinActivationHeight: 0,
				},
				Height: 0,
				Active: true,
			},
		},
		Warnings: "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.",
	}
	return info, nil
}

// gettxout
type TransactionOut struct {
	BestBlock     string       `json:"bestblock"`
	Confirmations uint32       `json:"confirmations"`
	Value         float64      `json:"value"`
	ScriptPubKey  ScriptPubKey `json:"scriptPubKey"`
	Coinbase      bool         `json:"coinbase"`
}

func GetTransactionData(bestblockhash string, txid string, tx *wire.MsgTx, voutIndex int, confirmations uint32) (TransactionOut, error) {
	voutArr := EncodeVOUTs(tx.TxOut)
	if len(voutArr) <= voutIndex {
		return TransactionOut{}, fmt.Errorf("vout index %d out of bounds, give 0-%d", voutIndex, len(voutArr)-1)
	}
	data := TransactionOut{
		BestBlock:     bestblockhash,
		Confirmations: confirmations,
		Value:         voutArr[voutIndex].Value,
		ScriptPubKey:  voutArr[voutIndex].ScriptPubKey,
		Coinbase:      false,
	}
	return data, nil
}

// gettxoutsetinfo
type BlockStats struct {
	Height          int     `json:"height"`
	BestBlock       string  `json:"bestblock"`
	TxOuts          int     `json:"txouts"`
	BogoSize        int     `json:"bogosize"`
	HashSerialized2 string  `json:"hash_serialized_2"`
	TotalAmount     float64 `json:"total_amount"`
	Transactions    int     `json:"transactions"`
	DiskSize        int     `json:"disk_size"`
}

func GetTxOutSetInfoFunc(bestblockhash string, height int) (BlockStats, error) {
	stats := BlockStats{
		Height:          height,
		BestBlock:       bestblockhash,
		TxOuts:          223,
		BogoSize:        16056,
		HashSerialized2: "2224c7b130595717437eeff9730085811f3a1870d76ac269d78dc2895f1de36d",
		TotalAmount:     8550.00000000,
		Transactions:    216,
		DiskSize:        16190,
	}
	return stats, nil
}
