// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package clique

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

const (
	// This is the amount of time spent waiting in between redialing a certain node. The
	// limit is a bit higher than inboundThrottleTime to prevent failing dials in small
	// private networks

	// Config for the  Round Robin Time
	dialStatsLogInterval = 100 * time.Second // For Each time

	// Endpoint resolution is throttled with bounded backoff.
	initialResolveDelay = 60 * time.Second
	maxResolveDelay     = time.Hour
)

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes)
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account
}

var count2 int = 0

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal
}

/* This struct will store Informaion of every node of Network.
@Owner: address of each node
@OStakes : The Number of stakes each node staked
@Timestamp : The timestamp of each node entry in the Network
@MiningPower : Mining Power of each node
*/
type TallyStake struct {
	Owner           common.Address `json:"owner"`
	OStakes         uint64         `json:"o_stakes"`
	Timestamp       time.Time      `json:"timestamp"`
	Reputation      uint64         `json:"reputation"`
	Delegated_count int            `json:"delegated_count"`
}

/* This struct will store the Information of selected nodes.
@Owner: address of selected node
@OStakes : The Number of stakes selected node staked
*/
// type TallyDelegatedStake struct {
// 	Owner   common.Address `json:"owner"`
// 	OStakes uint64         `json:"o_stakes"`
// }

/* This struct will store Informaion  of strong nodes in Network.
@Owner: address of strong node
@OStakes : The Number of stakes strong node staked
@MiningPower : Mining Power of strong node
@broadcast : broadcast or non broadcast strategy
*/
type TallyDelegatedStake struct {
	Owner               common.Address `json:"owner"`
	OStakes             uint64         `json:"o_stakes"`
	Timestamp           time.Time      `json:"timestamp"`
	Reputation          uint64         `json:"reputation"`
	Delegated_Count     int            `json:"delegated_count"`
	Invalid_Block       int            `json:"invalid_block"`
	Block_Game          int            `json:"block_games_played"`
	Current_game_plaing uint64         `json:"block_current_game_playing"`
}

/* This struct will store Informaion nodes who selected for miner.
@Owner: address of miner node
@OStakes : The Number of stakes miner node staked
@MiningPower : Mining Power of miner node
*/
type Minerpool struct {
	Owner                  common.Address `json:"owner"`
	OStakes                uint64         `json:"o_stakes"`
	Timestamp              time.Time      `json:"timestamp"`
	Reputation             uint64         `json:"reputation"`
	Delegated_Count        int            `json:"delegated_count"`
	Invalid_Block          int            `json:"invalid_block"`
	Block_Game             int            `json:"block_games_played"`
	Broadcast              int            `json:"broadcast_game"`
	Broadcast_Game         int            `json:"broadcast_game_played"`
	Curent_Broadcast_count uint64         `json:"cuurent_broadcast_play"`
	Eligible               bool           `json:"eligible"`
}

var games uint64 = 10000

// Snapshot is the state of the authorization voting at a given point in time.
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior
	sigcache *lru.ARCCache        // Cache of recent block signatures to speed up ecrecover

	Number              uint64                      `json:"number"`                // Block number where the snapshot was created
	Hash                common.Hash                 `json:"hash"`                  // Block hash where the snapshot was created
	Signers             map[common.Address]struct{} `json:"signers"`               // Set of authorized signers at this moment
	Recents             map[uint64]common.Address   `json:"recents"`               // Set of recent signers for spam protections
	Votes               []*Vote                     `json:"votes"`                 // List of votes cast in chronological order
	Tally               map[common.Address]Tally    `json:"tally"`                 // Current vote tally to avoid recalculating
	TallyStakes         []*TallyStake               `json:"tallystakes"`           // to hold all stakes mapped to their addresses // Abhi
	StakeSigner         common.Address              `json:"stakesigner"`           // Abhi
	TallyDelegatedStake []*TallyDelegatedStake      `json:"tally_delegated_stake"` //
	// StrongPool          []*StrongPool               `json:"strong_pool"`           //
	MinerPool        []*Minerpool                `json:"miner_pool"`        //
	DelegatedSigners map[common.Address]struct{} `json:"delegated_signers"` //
	malicious        bool                        //Find malicious node
	stage1           bool                        //stage 1 game
	stage2           bool                        //stage 2 game
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []common.Address

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use if for
// the genesis block.

func newSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	log.Info("printing signers of 0 address, ")
	log.Info(signers[0].String())

	var snap = &Snapshot{
		config:           config,
		sigcache:         sigcache,
		Number:           number,
		Hash:             hash,
		Signers:          make(map[common.Address]struct{}),
		Recents:          make(map[uint64]common.Address),
		Tally:            make(map[common.Address]Tally),
		StakeSigner:      signers[0],
		DelegatedSigners: make(map[common.Address]struct{}),
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{}
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
func loadSnapshot(config *params.CliqueConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte("clique-"), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte("clique-"), s.Hash[:]...), blob)
}

// copy creates a deep copy of the snapshot, though not the individual votes.
func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:      s.config,
		sigcache:    s.sigcache,
		Number:      s.Number,
		Hash:        s.Hash,
		Signers:     make(map[common.Address]struct{}),
		Recents:     make(map[uint64]common.Address),
		Votes:       make([]*Vote, len(s.Votes)),
		Tally:       make(map[common.Address]Tally),
		TallyStakes: make([]*TallyStake, len(s.TallyStakes)), // Abhi
		StakeSigner: s.StakeSigner,                           // Abhi
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.Tally {
		cpy.Tally[address] = tally
	}
	copy(cpy.Votes, s.Votes)
	copy(cpy.TallyStakes, s.TallyStakes)

	return cpy
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Signers[address]
	return (signer && !authorize) || (!signer && authorize)
}

// cast adds a new vote into the tally.
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1}
	}
	return true
}

// uncast removes a previously cast vote from the tally.
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address)
	}
	return true
}

func apply1() {
	for i := 1; i <= 5; i++ {
		if i == 5 {
			return
		}
	}
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	if len(headers) == 0 {
		log.Info("apply 202 error")
		return s, nil
	}
	// Sanity check that the headers can be applied
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain
			log.Info("apply 209 error")
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}
	// Iterate through the headers and create a new snapshot
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
			//snap.TallyStakes = nil
		}
		// Delete the oldest signer from the recent list to allow it signing again
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		signer, err := ecrecover(header, s.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok {
			log.Info("apply 240 error")
			//return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				//return nil, errRecentlySigned
				log.Info("recently signed")
			}
		}

		snap.Recents[number] = signer

		// Header authorized, discard any previous votes from the signer
		for i, vote := range snap.Votes {
			if vote.Signer == signer && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // only one vote allowed
			}
		}
		// Tally up the new vote from the signer
		//var authorize bool
		var in_stakes uint64 // Abhi
		var reputation uint64

		/*	switch {
			case bytes.Equal(header.Nonce[:], nonceAuthVote):
				authorize = true
			case bytes.Equal(header.Nonce[:], nonceDropVote):
				authorize = false
			default:
				return nil, errInvalidVote
			}*/

		in_stakes = header.Nonce.Uint64() // Abhi
		reputation = rep
		/*if snap.cast(header.Coinbase, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Signer:    signer,
				Block:     number,
				Address:   header.Coinbase,
				Authorize: authorize,
			})
		}*/
		// Abhi -Add stakes to snapshot

		log.Info("Checking----->")
		//log.Info(header.Coinbase.String())
		fmt.Println("coinbase", header.Coinbase)
		//log.Info(string(in_stakes))
		fmt.Println(in_stakes)
		var flag bool
		var posistion int
		flag = false
		for i := 0; i < len(snap.TallyStakes); i++ {
			if snap.TallyStakes[i].Owner == header.Coinbase {
				flag = true
				posistion = i
			}
		}
		if flag == false {
			var timestamp = time.Now()
			var l int = 10 + rand.Intn(10)
			snap.TallyStakes = append(snap.TallyStakes, &TallyStake{
				Owner:           header.Coinbase,
				OStakes:         in_stakes,
				Timestamp:       timestamp,
				Reputation:      uint64(int(reputation) + rand.Intn(9) + 80),
				Delegated_count: l,
			})
		} else {
			snap.TallyStakes[posistion].OStakes = in_stakes
		}

		fmt.Println("leangth", len(snap.TallyStakes))

		// If the vote passed, update the list of signers

		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Signers)/2 {
			if tally.Authorize {
				snap.Signers[header.Coinbase] = struct{}{}
			} else {
				delete(snap.Signers, header.Coinbase)

				// Signer list shrunk, delete any leftover recent caches
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signer cast
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.Coinbase {
						// Uncast the vote from the cached tally
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase)
		}

		startTime := time.Now()
		//Stage 1 Game
		avg := uint64(0)
		max := uint64(0)
		min := uint64(999)
		for i := 0; i < len(snap.TallyStakes); i++ {
			// add = add + snap.TallyStakes[i].OStakes
			// snap.TallyStakes[i].MiningPower = snap.TallyStakes[i].OStakes / 32
			if max < snap.TallyStakes[i].OStakes {
				max = snap.TallyStakes[i].OStakes
			}
			if min > snap.TallyStakes[i].OStakes && min >= 32 {
				min = snap.TallyStakes[i].OStakes
			}
		}
		// avg = add / uint64(len(snap.TallyStakes))
		// fmt.Println("avg:", add, avg)
		avg = max - (min / 2)
		var f1 bool
		for i := 0; i < len(snap.TallyStakes); i++ {
			f1 = false
			if snap.TallyStakes[i].OStakes >= 32 && snap.TallyStakes[i].OStakes <= avg {
				for j := 0; j < len(snap.TallyDelegatedStake); j++ {
					if snap.TallyStakes[i].Owner == snap.TallyDelegatedStake[j].Owner {
						f1 = true
						snap.TallyDelegatedStake[j].OStakes = snap.TallyStakes[i].OStakes
						snap.TallyDelegatedStake[j].Reputation = snap.TallyStakes[i].Reputation
						// snap.TallyDelegatedStake[j].MiningPower = snap.TallyStakes[i].MiningPower
						fmt.Println("Updated in TallyDelegated Stake")
						break
					}
				}
				if f1 == false {
					var n int = 10 + rand.Intn(10)
					var kl int = 60 + rand.Intn(10)
					snap.TallyDelegatedStake = append(snap.TallyDelegatedStake, &TallyDelegatedStake{
						Owner:               snap.TallyStakes[i].Owner,
						OStakes:             snap.TallyStakes[i].OStakes,
						Timestamp:           snap.TallyStakes[i].Timestamp,
						Reputation:          snap.TallyStakes[i].Reputation,
						Delegated_Count:     snap.TallyStakes[i].Delegated_count,
						Invalid_Block:       n,
						Block_Game:          kl,
						Current_game_plaing: 0,
						// MiningPower: snap.TallyStakes[i].MiningPower,
					})
					fmt.Println("Chosen TallyDelegatedStake")
				}

			}

		}

		// Stage two
		fmt.Println("Nodes in Network:- ")
		for i := 0; i < len(snap.TallyStakes); i++ {
			fmt.Println("Stakes = ", snap.TallyStakes[i].OStakes)
			fmt.Println("Owner = ", snap.TallyStakes[i].Owner)
			fmt.Println("Timestamp = ", snap.TallyStakes[i].Timestamp)
			fmt.Println("Reputation = ", snap.TallyStakes[i].Reputation)
			fmt.Println("Delegated count = ", snap.TallyStakes[i].Delegated_count)
			fmt.Println()
		}

		myList := []uint64{}
		myList2 := []int{}
		fmt.Println("Before Stage 1 TallyDelegatedStake Nodes")

		for i := 0; i < len(snap.TallyDelegatedStake); i++ {
			fmt.Println("OStakes = ", snap.TallyDelegatedStake[i].OStakes)
			fmt.Println("Owner = ", snap.TallyDelegatedStake[i].Owner)
			fmt.Println("Timestamp = ", snap.TallyDelegatedStake[i].Timestamp)
			fmt.Println("Delegated COunt = ", snap.TallyDelegatedStake[i].Delegated_Count)
			fmt.Println("Number of Invalid Blocks generated = ", snap.TallyDelegatedStake[i].Invalid_Block)
			fmt.Println("Number of Games played = ", snap.TallyDelegatedStake[i].Block_Game)
			fmt.Println("Reputation = ", snap.TallyDelegatedStake[i].Reputation)
			fmt.Println("Current Game played = ", snap.TallyDelegatedStake[i].Current_game_plaing)
			fmt.Println()
		}

		for i := 0; i < len(snap.TallyDelegatedStake); i++ {
			for j := i + 1; j < len(snap.TallyDelegatedStake); j++ {

				k := rand.Intn(2)
				m := rand.Intn(2)
				if k == 0 { //0 means invalid and 1 means valid
					snap.TallyDelegatedStake[i].OStakes = snap.TallyDelegatedStake[i].OStakes - (4 * snap.TallyDelegatedStake[i].OStakes / 10 * uint64(snap.TallyDelegatedStake[i].Invalid_Block) / uint64(snap.TallyDelegatedStake[i].Block_Game))
					snap.TallyDelegatedStake[i].Invalid_Block += 1
					snap.TallyDelegatedStake[i].Current_game_plaing += 1
					var hj uint64 = (4 * snap.TallyDelegatedStake[i].OStakes / 10 * uint64(snap.TallyDelegatedStake[i].Invalid_Block) / uint64(snap.TallyDelegatedStake[i].Block_Game))
					myList = append(myList, hj)

				}

				if m == 0 {
					snap.TallyDelegatedStake[j].OStakes = snap.TallyDelegatedStake[j].OStakes - (4 * snap.TallyDelegatedStake[j].OStakes / 10 * uint64(snap.TallyDelegatedStake[j].Invalid_Block) / uint64(snap.TallyDelegatedStake[j].Block_Game))
					snap.TallyDelegatedStake[j].Invalid_Block += 1
					snap.TallyDelegatedStake[j].Current_game_plaing += 1
					var hj uint64 = (4 * snap.TallyDelegatedStake[j].OStakes / 10 * uint64(snap.TallyDelegatedStake[j].Invalid_Block) / uint64(snap.TallyDelegatedStake[j].Block_Game))
					myList = append(myList, hj)
				}

				snap.TallyDelegatedStake[i].Block_Game += 1
				snap.TallyDelegatedStake[j].Block_Game += 1
			}
		}

		snap.stage1 = false

		fmt.Println("After Stage 1 TallyDelegatedStake Nodes")

		for i := 0; i < len(snap.TallyDelegatedStake); i++ {
			fmt.Println("OStakes = ", snap.TallyDelegatedStake[i].OStakes)
			fmt.Println("Owner = ", snap.TallyDelegatedStake[i].Owner)
			fmt.Println("Timestamp = ", snap.TallyDelegatedStake[i].Timestamp)
			fmt.Println("Delegated count = ", snap.TallyDelegatedStake[i].Delegated_Count)
			fmt.Println("Number of Invalid block = ", snap.TallyDelegatedStake[i].Invalid_Block)
			fmt.Println("Number of games played = ", snap.TallyDelegatedStake[i].Block_Game)
			fmt.Println("Reputation = ", snap.TallyDelegatedStake[i].Reputation)
			fmt.Println("Current game played = ", snap.TallyDelegatedStake[i].Current_game_plaing)
			fmt.Println()
		}

		for i := 0; i < len(snap.TallyDelegatedStake); i++ {
			f1 = false
			flag2 := 0
			if (100 * snap.TallyDelegatedStake[i].Current_game_plaing / uint64(len(snap.TallyDelegatedStake))) < 50 {
				for j := 0; j < len(snap.MinerPool); j++ {
					if snap.TallyDelegatedStake[i].Owner == snap.MinerPool[j].Owner {
						f1 = true
						snap.MinerPool[j].OStakes = snap.TallyDelegatedStake[i].OStakes
						snap.MinerPool[j].Reputation = snap.TallyDelegatedStake[i].Reputation
						// snap.TallyDelegatedStake[j].MiningPower = snap.TallyStakes[i].MiningPower
						fmt.Println("Updated in Mining Pool")
						break
					}
				}
			} else {
				for _, v := range myList2 {
					if v == i {
						flag2 = 1
						break
					}
				}
				if flag2 == 0 {
					myList2 = append(myList2, i)
				}
			}

			if f1 == false {
				var jk int = 10 + rand.Intn(10)
				var lk int = 60 + rand.Intn(10)
				snap.MinerPool = append(snap.MinerPool, &Minerpool{

					Owner:                  snap.TallyDelegatedStake[i].Owner,
					OStakes:                snap.TallyDelegatedStake[i].OStakes,
					Timestamp:              snap.TallyDelegatedStake[i].Timestamp,
					Reputation:             snap.TallyDelegatedStake[i].Reputation,
					Delegated_Count:        snap.TallyDelegatedStake[i].Delegated_Count,
					Invalid_Block:          snap.TallyDelegatedStake[i].Invalid_Block,
					Block_Game:             snap.TallyDelegatedStake[i].Block_Game,
					Broadcast:              jk,
					Broadcast_Game:         lk,
					Curent_Broadcast_count: 0,
					Eligible:               false,
					// MiningPower: snap.TallyStakes[i].MiningPower,
				})
				fmt.Println("Chosen Miner pool")
			}
		}

		myList1 := []uint64{}

		fmt.Println("Before Stage 2 Miner Nodes")

		for i := 0; i < len(snap.MinerPool); i++ {
			fmt.Println("OStakes = ", snap.MinerPool[i].OStakes)
			fmt.Println("Owner = ", snap.MinerPool[i].Owner)
			fmt.Println("Timestamp = ", snap.MinerPool[i].Timestamp)
			fmt.Println("Delegated Count = ", snap.MinerPool[i].Delegated_Count)
			fmt.Println("Number of Invalid Block generated = ", snap.MinerPool[i].Invalid_Block)
			fmt.Println("Number of Games played = ", snap.MinerPool[i].Block_Game)
			fmt.Println("Reputation = ", snap.MinerPool[i].Reputation)
			fmt.Println("Number of times Broadcast played = ", snap.MinerPool[i].Broadcast)
			fmt.Println("Number of games played = ", snap.MinerPool[i].Broadcast_Game)
			fmt.Println("Current Broadcast played = ", snap.MinerPool[i].Curent_Broadcast_count)
			fmt.Println()
		}

		for i := 0; i < len(snap.MinerPool); i++ {
			for j := i + 1; j < len(snap.MinerPool); j++ {
				k := rand.Intn(2)
				m := rand.Intn(2)
				if k == 0 { //0 means broadcast and 1 means non-broadcast
					snap.MinerPool[i].Reputation = snap.MinerPool[i].Reputation - (4 * snap.MinerPool[i].Reputation / 10 * uint64(snap.MinerPool[i].Broadcast) / uint64(snap.MinerPool[i].Broadcast_Game))
					snap.MinerPool[i].Curent_Broadcast_count += 1
					snap.MinerPool[i].Broadcast += 1
					var hj uint64 = (4 * snap.MinerPool[i].Reputation / 10 * uint64(snap.MinerPool[i].Broadcast) / uint64(snap.MinerPool[i].Broadcast_Game))
					myList1 = append(myList1, hj)
				}

				if m == 0 {
					snap.MinerPool[j].Reputation = snap.MinerPool[j].Reputation - (4 * snap.MinerPool[j].Reputation / 10 * uint64(snap.MinerPool[j].Broadcast) / uint64(snap.MinerPool[j].Broadcast_Game))
					snap.MinerPool[j].Curent_Broadcast_count += 1
					snap.MinerPool[j].Broadcast += 1
					var hj uint64 = (4 * snap.MinerPool[j].Reputation / 10 * uint64(snap.MinerPool[j].Broadcast) / uint64(snap.MinerPool[j].Broadcast_Game))
					myList1 = append(myList1, hj)
				}

				snap.MinerPool[i].Broadcast_Game += 1
				snap.MinerPool[j].Broadcast_Game += 1
			}
		}

		snap.stage2 = false

		fmt.Println("After Stage 2 Miner Nodes")

		for i := 0; i < len(snap.MinerPool); i++ {
			fmt.Println("OStakes = ", snap.MinerPool[i].OStakes)
			fmt.Println("Owner = ", snap.MinerPool[i].Owner)
			fmt.Println("Timestamp = ", snap.MinerPool[i].Timestamp)
			fmt.Println("Delegated Count = ", snap.MinerPool[i].Delegated_Count)
			fmt.Println("Number of Invalid Block played = ", snap.MinerPool[i].Invalid_Block)
			fmt.Println("Number of Games played = ", snap.MinerPool[i].Block_Game)
			fmt.Println("Reputation = ", snap.MinerPool[i].Reputation)
			fmt.Println("Number of times Broadcast played = ", snap.MinerPool[i].Broadcast)
			fmt.Println("Number of games played = ", snap.MinerPool[i].Broadcast_Game)
			fmt.Println("Current broadcast played = ", snap.MinerPool[i].Curent_Broadcast_count)
			fmt.Println()
		}

		for i := 0; i < len(snap.MinerPool); i++ {
			flag2 := 0
			if (100 * snap.MinerPool[i].Curent_Broadcast_count / uint64(len(snap.MinerPool))) < 40 {
				snap.MinerPool[i].Eligible = true
			} else {
				for _, v := range myList2 {
					if v == i {
						flag2 = 1
						break
					}
				}

				if flag2 == 0 {
					myList2 = append(myList2, i)
				}
			}
		}

		var count_eligible uint64 = 0
		for i := 0; i < len(snap.MinerPool); i++ {
			if snap.MinerPool[i].Eligible {
				count_eligible += 1
			}
		}

		fmt.Println("Number of Eligible nodes = ", count_eligible)
		if count_eligible > 2 && count2 < 3 {
			apply1()
			count2 += 1
		}

		var rep uint64 = 1
		var rep1 uint64 = 1
		var index int
		var index1 int
		var max_address1 common.Address
		var max_address2 common.Address
		for i := 0; i < len(snap.MinerPool); i++ {
			if snap.MinerPool[i].Eligible {
				if snap.MinerPool[i].Reputation > rep && snap.MinerPool[i].Reputation != 100 {
					rep = snap.MinerPool[i].Reputation
					index = i
					fmt.Println("Eligible = ", snap.MinerPool[i].Owner)
					max_address1 = snap.MinerPool[i].Owner
				}
			}
		}

		if index != -1 {
			for i := 0; i < len(snap.MinerPool); i++ {
				if snap.MinerPool[i].Eligible {
					if snap.MinerPool[index].Owner != snap.MinerPool[i].Owner {
						if snap.MinerPool[i].Reputation > rep1 && rep != snap.MinerPool[i].Reputation && snap.MinerPool[i].Reputation != 100 {
							rep1 = snap.MinerPool[i].Reputation
							index1 = i
							fmt.Println("2nd Eligible = ", snap.MinerPool[i].Owner)
							max_address2 = snap.MinerPool[i].Owner
						}
					}
				}
			}
		}

		fmt.Println(index1)
		var max_address common.Address
		if rep > rep1 {
			max_address = max_address1
		} else {
			max_address = max_address2
		}
		snap.StakeSigner = max_address

		fmt.Println("Miner Selected ", snap.StakeSigner)

		endTime := time.Now()
		duration := endTime.Sub(startTime)
		fmt.Println("Execution Time: ", duration)
		if len(myList) > 0 {
			sort.Slice(myList, func(i, j int) bool {
				return myList[i] < myList[j]
			})

		}
		if len(myList) > 0 {
			sort.Slice(myList1, func(i, j int) bool {
				return myList1[i] < myList1[j]
			})
		}

		fmt.Println("Payoff Matrix for Second Stage Game")
		if len(myList) > 0 {
			fmt.Println("--------------------------------")
			fmt.Println("|   ", 0, " , ", 0, "|", 0, ",", int(-myList[0])*7, "|")
			fmt.Println("----------------------------------")
			fmt.Println("|   ", int(-myList[0])*7, ",", 0, " | ", int(-myList[0])*7, ",", int(-myList[0])*7, "|")
			fmt.Println("--------------------------------")
		}
		fmt.Println("Payoff Matrix for Third Stage Game")
		if len(myList1) > 0 {
			fmt.Println("-----------------------")
			fmt.Println("|   ", -1*float64(myList1[0])/float64(100), ",", -1*float64(myList1[0])/float64(100), "|", -1*float64(myList1[0])/float64(100), ",", 0, "|")
			fmt.Println("-----------------------")
			fmt.Println("|   ", 0, ",", -1*float64(myList1[0])/float64(100), " | ", 0, " , ", 0, "|")
			fmt.Println("-----------------------")
		}

		fmt.Println("Number of malicious nodes = ", len(myList2))
		// If we're taking too much time (ecrecover), notify the user once a while
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()

	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(signersAscending(sigs))
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset)
}
