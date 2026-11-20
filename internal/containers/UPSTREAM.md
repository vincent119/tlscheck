# 受控 PKCS#12 來源

來源：SSLMate go-pkcs12 v0.7.4，commit 0bb5b30d698b67e51be1462870f57f3e0bfc7067。
授權：本目錄 LICENSE（BSD-3-Clause），保留原著作權聲明。

保留上游 PKCS#12 KDF 與 BMP 密碼編碼；容器型別、CBC padding／PBES2解碼與MAC驗證由原來源裁剪為解碼專用。PBKDF2使用Go標準庫，不引入x/crypto。
新增受控入口負責MAC必備、SHA-256／PBES2-PBKDF2-HMAC-SHA256-AES256-CBC白名單、原子結果、單私鑰、資源與深度限制。P7B為有限標準ASN.1解析。
產品不包含encoder、RC2／DES、PBMAC1、上游寬鬆DecodeChain／ToPEM或BER轉換。

本專案已核准的加密規範例外僅適用此容器解碼及必要PKCS#12 KDF，其他加密原語維持標準crypto實作。上游演算法輸出不自行更改；來源升級須核對差異與對應回歸。
資源限制只約束可見內容／衍生工作量，不是RSS或硬時間隔離。Go字串與GC不能保證密碼副本零殘留。
