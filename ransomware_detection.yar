import "math"

/*
  INS3201 - Nhom 2 - Luat YARA (phien ban 2.1, da sua so voi ban 2.0)
  Quet:  yara -r detection/ransomware_detection.yar /home/ubuntu/
  Test:  yara detection/ransomware_detection.yar tests/yara_sample.txt
*/

rule Ransomware_Python_Hybrid_INS3201
{
    meta:
        description = "Phat hien script ma hoa Python (hybrid AES/RSA) cua mo phong INS3201"
        author = "Nhom 2 - INS3201"
        version = "2.1"

    strings:
        $s1 = "cryptography.hazmat.primitives.ciphers" ascii
        $s2 = "READ_ME_NOW.txt" ascii
        $s3 = ".LOCKED" ascii

    condition:
        filesize < 5MB and all of ($s*)
}

rule Ransomware_Encrypted_File_INS3201
{
    meta:
        description = "File .LOCKED: 2 byte dau = do dai khoa AES ma hoa RSA-2048 (256 = 0x0100), entropy cao"
        author = "Nhom 2 - INS3201"
        version = "2.1"

    condition:
        uint16be(0) == 0x0100 and
        filesize > 274 and filesize < 50MB and     // 2 + 256 (khoa) + 16 (IV) + >=1 block
        math.entropy(0, filesize) > 7.0            // file nho (~300 byte) chi dat ~7.3 nen khong dung 7.5
}
