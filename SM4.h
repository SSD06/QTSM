#ifndef SM4_H
#define SM4_H

#include <QByteArray>

struct evp_cipher_ctx_st;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

struct evp_cipher_st;
typedef struct evp_cipher_st EVP_CIPHER;

/**
 * @brief The SM4 class
 * 封装国密SM2加密算法，支持多种加密模式，并且每种模式均允许对无限长数据进行加密。
 * 参数含义如下：
 * -in 输入数据
 * -out 输出数据
 * -key 秘钥，秘钥长度必须为128位
 * -iv 初始化向量
 * -enc true表示加密，false表示解密
 */
class  SM4
{
public:
    SM4();
    ~SM4();

    bool ecb_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, bool enc);
    bool cbc_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool cfb1_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool cfb8_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool cfb128_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool ofb_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool ctr_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    bool gcm_encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, bool enc);
    static void generateKey(QByteArray &key,QByteArray &iv);
private:
    bool encrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, const EVP_CIPHER *ciper);
    bool decrypt(const QByteArray& in, QByteArray& out, const QByteArray& key, const QByteArray& iv, const EVP_CIPHER *ciper);

private:
    EVP_CIPHER_CTX *ctx;
};

#endif // SM4_H
