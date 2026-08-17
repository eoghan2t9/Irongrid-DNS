// Package shardutil provides the FNV-1a key-to-shard hash shared by the
// server's sharded-map guards (rate limiter, NX guard, connection limiter,
// login guard): each hashes a client key and indexes into a fixed-size array
// of independently-locked shards, trading one global lock for many small
// ones so concurrent clients rarely contend with each other.
package shardutil

// FNV1a hashes key with the 32-bit FNV-1a algorithm (cheap, decent spread).
// Callers mask the result to their own shard count: shardutil.FNV1a(key) &
// (n-1), where n is a power of two.
func FNV1a(key string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return h
}
