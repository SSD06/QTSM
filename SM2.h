#ifndef SM2_H
#define SM2_H

#include <QString>
enum class  CurveName
{
    sm2p256v1,
    prime256v1,
    secp256k1,
    secp384r1,
    secp521r1,
    sect233k1,
    sect233r1,
    sect409k1,
    sect409r1,
    sect571k1,
    sect571r1,
    brainpoolP256r1,
    brainpoolP256t1,
    brainpoolP384r1,
    brainpoolP384t1,
    brainpoolP512r1,
    brainpoolP512t1
};

class  SM2
{
public:
    // 生成秘钥对
    static bool generateKeyPair(QByteArray& priKey, QByteArray& pubKey);
    static bool generateKeyPair(QByteArray& priKey, QByteArray& pubKey,const CurveName &name);
    static bool generateKeyPair(const QString& priKeyFile, const QString& pubKeyFile);
    static bool generateKeyPUBPair(QByteArray& priKey,QByteArray& pubKey);

    // 对数据进行加解密
    static bool encrypt(const QByteArray& in, QByteArray& out, const QByteArray& pubKey);
    static bool decrypt(const QByteArray& in, QByteArray& out, const QByteArray& priKey);
    static QByteArray encrypt(const QByteArray& in,const QByteArray& pubKey);
    static QByteArray decrypt(const QByteArray& in,const QByteArray& priKey);

    static bool encryptpri(const QByteArray& in, QByteArray& out, const QByteArray& priKey);
    static bool decryptpub(const QByteArray& in, QByteArray& out, const QByteArray& pubKey);

    // 对摘要进行签名和验签
    static bool sign(const QByteArray& digest, QByteArray& sign, const QByteArray& priKey);
    static bool verify(const QByteArray& digest, const QByteArray& sign, const QByteArray& pubKey);
    //bool verify(const QByteArray& digest, QByteArray& sign, const QByteArray& pubKey);
};

#endif // SM2_H
