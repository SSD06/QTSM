#include "SM4.h"
#include <openssl/sms4.h>
#include <openssl/evp.h>
#include<openssl/rand.h>
#include<QDebug>
SM4::SM4()
{
    // 初始化CTX
    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

}

SM4::~SM4()
{
    // 释放CTX
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
}

bool SM4::ecb_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, QByteArray(), EVP_sms4_ecb());
    }
    else
    {
        return decrypt(in, out, key, QByteArray(), EVP_sms4_ecb());
    }
}

bool SM4::cbc_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_cbc());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_cbc());
    }
}

bool SM4::cfb1_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_cfb1());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_cfb1());
    }
}

bool SM4::cfb8_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_cfb8());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_cfb8());
    }
}

bool SM4::cfb128_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_cfb128());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_cfb128());
    }
}

bool SM4::ofb_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_ofb());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_ofb());
    }
}

bool SM4::ctr_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_ctr());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_ctr());
    }
}

bool SM4::gcm_encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, bool enc)
{
    if (enc)
    {
        return encrypt(in, out, key, iv, EVP_sms4_gcm());
    }
    else
    {
        return decrypt(in, out, key, iv, EVP_sms4_gcm());
    }
}

void SM4::generateKey(QByteArray &key, QByteArray &iv)
{
    unsigned char keyc[16],ivc[16];
    RAND_bytes(keyc,16);
    RAND_bytes(ivc,16);

    key=QByteArray((char*)keyc,16);
    iv=QByteArray((char*)ivc,16);
}

bool SM4::encrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, const EVP_CIPHER *ciper)
{
    // 秘钥长度必须为128位
    Q_ASSERT(key.size() == SMS4_KEY_LENGTH);
    //qDebug()<<key.size();
    // 指定加密算法及key和iv
    int ret = EVP_EncryptInit_ex(ctx, ciper, NULL, (const unsigned char*)key.data(), (const unsigned char*)iv.data());
    if(ret != 1)
    {
        return false;
    }

    // 进行加密操作
    int mlen = 0;
    out.resize(in.size() + SMS4_BLOCK_SIZE);
    ret = EVP_EncryptUpdate(ctx, (unsigned char*)out.data(), &mlen, (const unsigned char*)in.data(), in.size());
    if(ret != 1)
    {
        return false;
    }

    // 结束加密操作
    int flen = 0;
    ret = EVP_EncryptFinal_ex(ctx, (unsigned char *)out.data() + mlen, &flen);
    if(ret != 1)
    {
        return false;
    }
    out.resize(mlen + flen);
    return true;
}

bool SM4::decrypt(const QByteArray &in, QByteArray &out, const QByteArray &key, const QByteArray &iv, const EVP_CIPHER *ciper)
{
    // 秘钥长度必须为128位
    Q_ASSERT(key.size() == SMS4_KEY_LENGTH);

    // 指定解密算法及key和iv
    int ret = EVP_DecryptInit_ex(ctx, ciper, NULL, (const unsigned char*)key.data(), (const unsigned char*)iv.data());
    if(ret != 1)
    {
        return false;
    }

    // 进行解密操作
    int mlen = 0;
    out.resize(in.size());
    ret = EVP_DecryptUpdate(ctx, (unsigned char*)out.data(), &mlen, (const unsigned char*)in.data(), in.size());
    if(ret != 1)
    {
        return false;
    }

    // 结束解密操作
    int flen = 0;
    ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)out.data() + mlen, &flen);
    if(ret != 1)
    {
        return false;
    }
    out.resize(mlen + flen);
    return true;
}
