package filetxn

// securityState 保存原生安全描述，不包含報告或設定內容。
type securityState struct {
	Data     []byte
	UID, GID uint32
}
