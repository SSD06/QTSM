#include "SM3.h"
#include <openssl/sm3.h>
#include <openssl/evp.h>

SM3::SM3()
{
    // 初始化CTX
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
}

SM3::~SM3()
{
    // 释放CTX
    EVP_MD_CTX_free(ctx);
}

/**
 * @brief SM3::digest
 * 计算一段数据的摘要信息
 * @param data 输入数据，数据长度无限制。
 * @return 摘要信息，固定长度为32字节。计算失败时返回QByteArray大小为0
 */
QByteArray SM3::digest(const QByteArray &data)
{
    // 指定加密算法
    if (EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr) != 1)
    {
        return QByteArray();
    }

    // 进行加密操作
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
    {
        return QByteArray();
    }

    // 结束加密操作
    unsigned int flen = 0;
    QByteArray dige(SM3_DIGEST_LENGTH, 0);
    if (EVP_DigestFinal_ex(ctx, (unsigned char *)dige.data(), &flen) != 1)
    {
        return QByteArray();
    }
    return dige;
}
