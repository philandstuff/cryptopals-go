package cryptopals

func Transpose(chunks [][]byte) [][]byte {
	newChunks := make([][]byte, len(chunks[0]))
	for i := range newChunks {
		newChunks[i] = make([]byte, len(chunks))
		for j := range newChunks[i] {
			newChunks[i][j] = chunks[j][i]
		}
	}
	return newChunks
}
