#include "SM2.h"
#include <openssl/pem.h>
#include <openssl/sm2.h>
#include<QDebug>
#define SUCCEED                         1
#define SM2_MAX_PLAINTEXT_LENGTH		65535
#define SM2_MAX_CIPHERTEXT_LENGTH		(SM2_MAX_PLAINTEXT_LENGTH + 2048)

/**
 * @brief privateToEcKey
 * 将私钥数据转换为EC_KEY指针
 * @param key 私钥数据
 * @return EC_KEY指针
 */
EC_KEY* privateToEcKey(const QByteArray& key)
{
    BIO* bio = BIO_new_mem_buf(key.data(), key.size());
    if (bio == nullptr)
    {
        return nullptr;
    }

    EC_KEY* ecKey = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return ecKey;
}

/**
 * @brief publicToEcKey
 * 将公钥数据转换为EC_KEY指针
 * @param key 公钥数据
 * @return EC_KEY指针
 */
EC_KEY* publicToEcKey(const QByteArray& key)
{
    BIO* bio = BIO_new_mem_buf(key.data(), key.size());
    if (bio == nullptr)
    {
        return nullptr;
    }

    EC_KEY* ecKey = PEM_read_bio_EC_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return ecKey;
}

/**
 * @brief SM2::generateKeyPair
 * 生成密钥对
 * @param priKey 生成的私钥
 * @param pubKey 生成的公钥
 * @return 执行结果
 */
bool SM2::generateKeyPair(QByteArray &priKey, QByteArray &pubKey)
{
    // 创建EC_KEY对象
    EC_KEY* ecKey = EC_KEY_new();
    if (ecKey == nullptr)
    {
        return false;
    }

    // 创建EC_GROUP对象
    EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecGroup == nullptr)
    {
        EC_KEY_free(ecKey);
        return false;
    }

    // 设置EC_KEY对象的EC_GROUP
    if (EC_KEY_set_group(ecKey, ecGroup) != SUCCEED)
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建一个私钥
    if (!EC_KEY_generate_key(ecKey))
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建内存缓冲区
    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    // 私钥和公钥分别写入缓冲区
    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    // 从缓冲区读取至privateKey、publicKey
    int pri_len = BIO_pending(pri); // 获取缓冲区中待读取大小
    int pub_len = BIO_pending(pub);
    priKey.resize(pri_len);
    pubKey.resize(pub_len);
    BIO_read(pri, priKey.data(), pri_len);
    BIO_read(pub, pubKey.data(), pub_len);

    // 释放内存缓冲区
    BIO_free_all(pub);
    BIO_free_all(pri);

    // 释放EC_GROUP、EC_KEY
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return true;
}

bool SM2::generateKeyPair(QByteArray &priKey, QByteArray &pubKey, const CurveName &name)
{
    // 创建EC_KEY对象
    EC_KEY* ecKey = EC_KEY_new();
    if (ecKey == nullptr)
    {
        return false;
    }

    // 创建EC_GROUP对象

    EC_GROUP* ecGroup;
    if(name==CurveName::sm2p256v1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    }
    else if(name==CurveName::prime256v1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    }
    else if(name==CurveName::secp256k1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
    }
    else if(name==CurveName::secp384r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_secp384r1);
    }
    else if(name==CurveName::secp521r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_secp521r1);
    }

    else if(name==CurveName::sect233k1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect233k1);
    }
    else if(name==CurveName::sect233r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect233r1);
    }
    else if(name==CurveName::sect409k1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect409k1);
    }
    else if(name==CurveName::sect409r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect409r1);
    }
    else if(name==CurveName::sect571k1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect571k1);
    }
    else if(name==CurveName::sect571r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sect571r1);
    }

    else if(name==CurveName::brainpoolP256r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP256r1);
    }
    else if(name==CurveName::brainpoolP256t1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP256t1);
    }
    else if(name==CurveName::brainpoolP384r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP384r1);
    }
    else if(name==CurveName::brainpoolP384t1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP384t1);
    }
    else if(name==CurveName::brainpoolP512r1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP512r1);
    }
    else if(name==CurveName::brainpoolP512t1)
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_brainpoolP512t1);
    }

    else
    {
        ecGroup= EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    }
    if (ecGroup == nullptr)
    {
        EC_KEY_free(ecKey);
        return false;
    }

    // 设置EC_KEY对象的EC_GROUP
    if (EC_KEY_set_group(ecKey, ecGroup) != SUCCEED)
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建一个私钥
    if (!EC_KEY_generate_key(ecKey))
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建内存缓冲区
    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    // 私钥和公钥分别写入缓冲区
    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    // 从缓冲区读取至privateKey、publicKey
    int pri_len = BIO_pending(pri); // 获取缓冲区中待读取大小
    int pub_len = BIO_pending(pub);
    priKey.resize(pri_len);
    pubKey.resize(pub_len);
    BIO_read(pri, priKey.data(), pri_len);
    BIO_read(pub, pubKey.data(), pub_len);

    // 释放内存缓冲区
    BIO_free_all(pub);
    BIO_free_all(pri);

    // 释放EC_GROUP、EC_KEY
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return true;
}

/**
 * @brief SM2::generateKeyPair
 * 生成秘钥对文件
 * @param priKeyFile 私钥文件路径
 * @param pubKeyFile 公钥文件路径
 * @return 执行结果
 */
bool SM2::generateKeyPair(const QString &priKeyFile, const QString &pubKeyFile)
{
    // 创建EC_KEY对象
    EC_KEY* ecKey = EC_KEY_new();
    if (ecKey == nullptr)
    {
        return false;
    }

    // 创建EC_GROUP对象
    EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecGroup == nullptr)
    {
        EC_KEY_free(ecKey);
        return false;
    }

    // 设置EC_KEY对象的EC_GROUP
    if (EC_KEY_set_group(ecKey, ecGroup) != SUCCEED)
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建一个私钥
    if (!EC_KEY_generate_key(ecKey))
    {
        EC_GROUP_free(ecGroup);
        EC_KEY_free(ecKey);
        return false;
    }

    // 创建文件
    BIO* pri = BIO_new_file(priKeyFile.toStdString().c_str(), "w");
    BIO* pub = BIO_new_file(pubKeyFile.toStdString().c_str(), "w");

    // 私钥和公钥分别写入文件
    PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    // 释放文件bio
    BIO_free_all(pub);
    BIO_free_all(pri);

    // 释放EC_GROUP、EC_KEY
    EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return true;
}

bool SM2::generateKeyPUBPair(QByteArray &priKey, QByteArray &pubKey)
{
    // 创建EC_KEY对象
    EC_KEY* ecKey = privateToEcKey(priKey);
    if (ecKey == nullptr)
    {
        return false;
    }

    // 创建EC_GROUP对象
    //        EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    //        if (ecGroup == nullptr)
    //        {
    //            EC_KEY_free(ecKey);
    //            return false;
    //        }

    //        // 设置EC_KEY对象的EC_GROUP
    //        if (EC_KEY_set_group(ecKey, ecGroup) != SUCCEED)
    //        {
    //            EC_GROUP_free(ecGroup);
    //            EC_KEY_free(ecKey);
    //            return false;
    //        }

    // 创建一个私钥
    // if (!EC_KEY_generate_key(ecKey))
    // {
    //     EC_GROUP_free(ecGroup);
    //     EC_KEY_free(ecKey);
    //     return false;
    // }

    // 创建内存缓冲区
    //BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    // 私钥和公钥分别写入缓冲区
    //PEM_write_bio_ECPrivateKey(pri, ecKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_EC_PUBKEY(pub, ecKey);

    // 从缓冲区读取至privateKey、publicKey
    //int pri_len = BIO_pending(pri); // 获取缓冲区中待读取大小
    int pub_len = BIO_pending(pub);
    //priKey.resize(pri_len);
    pubKey.resize(pub_len);
    //BIO_read(pri, priKey.data(), pri_len);
    BIO_read(pub, pubKey.data(), pub_len);

    // 释放内存缓冲区
    BIO_free_all(pub);
    //BIO_free_all(pri);

    // 释放EC_GROUP、EC_KEY
    //EC_GROUP_free(ecGroup);
    EC_KEY_free(ecKey);
    return true;
}

/**
 * @brief SM2::encrypt
 * 对数据进行加密
 * @param in 明文数据，长度必须<=65535字节
 * @param out 密文数据
 * @param pubKey 公钥
 * @return 执行结果
 */
bool SM2::encrypt(const QByteArray &in, QByteArray &out, const QByteArray &pubKey)
{
    // 明文长度必须<=65535字节
    Q_ASSERT(in.size() <= SM2_MAX_PLAINTEXT_LENGTH);

    // 根据公钥数据生成EC_KEY
    EC_KEY* ecKey = publicToEcKey(pubKey);
    if (ecKey == nullptr)
    {
        return false;
    }
    // 获取输入数据加密后的长度

    size_t encrypted_len = 0;
    if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     nullptr, &encrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }

    // 执行加密
    out.resize(encrypted_len); // 调整目的缓冲区大小
    if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     (unsigned char*)out.data(), &encrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }
    out.resize(encrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
    return true;
}

/**
 * @brief SM2::decrypt
 * 对数据进行解密
 * @param in 密文数据，长度必须<=(65535+2048)字节，即65535字节明文加密后的最大长度
 * @param out 输出解密后的数据
 * @param priKey 私钥
 * @return 执行结果
 */
bool SM2::decrypt(const QByteArray &in, QByteArray &out, const QByteArray &priKey)
{
    // 密文长度必须<=(65535+2048)字节
    //Q_ASSERT(in.size() <= SM2_MAX_CIPHERTEXT_LENGTH);

    // 根据私钥数据生成EC_KEY
    EC_KEY* ecKey = privateToEcKey(priKey);
    if (ecKey == nullptr)
    {
        return false;
    }



    // 获取输入数据解密后的长度
    size_t decrypted_len = 0;
    if (SM2_decrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     nullptr, &decrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }

    // 执行解密
    out.resize(decrypted_len); // 调整目的缓冲区大小
    if (SM2_decrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     (unsigned char*)out.data(), &decrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }
    out.resize(decrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
    return true;

}

QByteArray SM2::encrypt(const QByteArray &in, const QByteArray &pubKey)
{
    QByteArray out;
    EC_KEY* ecKey = publicToEcKey(pubKey);
    if (ecKey == nullptr)
    {
        out.clear();
        return out;
    }
    // 获取输入数据加密后的长度
    if(in.size() <= SM2_MAX_PLAINTEXT_LENGTH)
    {
        size_t encrypted_len = 0;
        if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                         nullptr, &encrypted_len, ecKey) != SUCCEED)
        {
            out.clear();
            return out;
        }

        // 执行加密
        out.resize(encrypted_len); // 调整目的缓冲区大小
        if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                         (unsigned char*)out.data(), &encrypted_len, ecKey) != SUCCEED)
        {
            out.clear();
            return out;
        }
        out.resize(encrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
        return out.toBase64();
    }
    else
    {
        //qDebug()<<in.size()<<"明文长度";
        QByteArray out2;
        QByteArray in2;
        int size=in.size();
        for(int i=0;i<size;i+=SM2_MAX_PLAINTEXT_LENGTH)
        {
            in2.clear();
            out2.clear();
            in2=in.mid(i,SM2_MAX_PLAINTEXT_LENGTH);
            if(in2.isEmpty())
            {
                continue;
            }
            size_t encrypted_len = 0;
            if (SM2_encrypt_with_recommended((const unsigned char*)in2.data(), in2.size(),
                                             nullptr, &encrypted_len, ecKey) != SUCCEED)
            {
                //qDebug()<<i<<"加密失败1"<<in2.size();

                out.clear();
                return out;
            }

            // 执行加密
            out2.resize(encrypted_len); // 调整目的缓冲区大小
            if (SM2_encrypt_with_recommended((const unsigned char*)in2.data(), in2.size(),
                                             (unsigned char*)out2.data(), &encrypted_len, ecKey) != SUCCEED)
            {
                //qDebug()<<i<<"加密失败2";
                out.clear();
                return out;
            }
            out2.resize(encrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
            //qDebug()<<in2.size()<<out2.size();
            out+=out2.toBase64()+QString(" ");
        }
        //qDebug()<<out.size()<<"加密后长度";
        return out;
    }
}

QByteArray SM2::decrypt(const QByteArray &in, const QByteArray &priKey)
{
    // 根据私钥数据生成EC_KEY
    QByteArray out;
    EC_KEY* ecKey = privateToEcKey(priKey);
    if (ecKey == nullptr)
    {
        out.clear();
        return out;
    }

    QList<QByteArray> bytelist=in.split(' ');
    QByteArray out2;
    for(auto &byte64:bytelist)
    {
        if(byte64.isEmpty())
        {
            continue;
        }
        QByteArray byte=QByteArray::fromBase64(byte64);
        // 获取输入数据解密后的长度
        size_t decrypted_len = 0;
        if (SM2_decrypt_with_recommended((const unsigned char*)byte.data(), byte.size(),
                                         nullptr, &decrypted_len, ecKey) != SUCCEED)
        {
            //qDebug()<<"解密失败1"<<out;
            out.clear();
            return out;
        }

        // 执行解密
        out2.resize(decrypted_len); // 调整目的缓冲区大小
        if (SM2_decrypt_with_recommended((const unsigned char*)byte.data(), byte.size(),
                                         (unsigned char*)out2.data(), &decrypted_len, ecKey) != SUCCEED)
        {
            //qDebug()<<"解密失败1"<<out;
            out.clear();
            return out;
        }
        out2.resize(decrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
        out+=out2;
    }
    return out;
}

bool SM2::encryptpri(const QByteArray &in, QByteArray &out, const QByteArray &priKey)
{
    // 明文长度必须<=65535字节
    Q_ASSERT(in.size() <= SM2_MAX_PLAINTEXT_LENGTH);

    // 根据公钥数据生成EC_KEY
    EC_KEY* ecKey = privateToEcKey(priKey);
    if (ecKey == nullptr)
    {
        return false;
    }

    // 获取输入数据加密后的长度
    size_t encrypted_len = 0;
    if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     nullptr, &encrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }

    // 执行加密
    out.resize(encrypted_len); // 调整目的缓冲区大小
    if (SM2_encrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     (unsigned char*)out.data(), &encrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }
    out.resize(encrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
    return true;
}

bool SM2::decryptpub(const QByteArray &in, QByteArray &out, const QByteArray &pubKey)
{
    // 密文长度必须<=(65535+2048)字节
    Q_ASSERT(in.size() <= SM2_MAX_CIPHERTEXT_LENGTH);

    // 根据私钥数据生成EC_KEY
    EC_KEY* ecKey = publicToEcKey(pubKey);
    if (ecKey == nullptr)
    {
        return false;
    }

    // 获取输入数据解密后的长度
    size_t decrypted_len = 0;
    if (SM2_decrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     nullptr, &decrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }

    // 执行解密
    out.resize(decrypted_len); // 调整目的缓冲区大小
    if (SM2_decrypt_with_recommended((const unsigned char*)in.data(), in.size(),
                                     (unsigned char*)out.data(), &decrypted_len, ecKey) != SUCCEED)
    {
        return false;
    }
    out.resize(decrypted_len); // 必须再次调整为实际大小，有可能前后2次长度不一致
    return true;
}

/**
 * @brief SM2::sign
 * 对摘要进行签名
 * @param digest 摘要信息
 * @param sign 输出签名数据
 * @param priKey 私钥
 * @return 执行结果
 */
bool SM2::sign(const QByteArray &digest, QByteArray &sign, const QByteArray &priKey)
{
    // 根据私钥数据生成EC_KEY
    EC_KEY* ecKey = privateToEcKey(priKey);
    if (ecKey == nullptr)
    {
        return false;
    }

    // 对摘要进行签名
    unsigned int siglen = 0;
    sign.resize(SM2_MAX_SIGNATURE_LENGTH);
    if (SM2_sign(NID_undef, (const unsigned char*)digest.data(), digest.size(),
                 (unsigned char*)sign.data(), &siglen, ecKey) != SUCCEED)
    {
        return false;
    }
    sign.resize(siglen); // 调整为实际大小
    return true;
}

/**
 * @brief SM2::verify
 * 对摘要和签名进行验签
 * @param digest 摘要信息
 * @param sign 签名数据
 * @param pubKey 公钥
 * @return 验签结果
 */
bool SM2::verify(const QByteArray &digest, const QByteArray &sign, const QByteArray &pubKey)
//bool SM2::verify(const QByteArray &digest, QByteArray &sign, const QByteArray &pubKey)
{
    // 根据公钥数据生成EC_KEY
    EC_KEY* ecKey = publicToEcKey(pubKey);
    if (ecKey == nullptr)
    {
        return false;
    }

    // 对摘要和签名数据进行验签
    int ret = SM2_verify(NID_undef, (const unsigned char*)digest.data(), digest.size(),
                         (unsigned char *)sign.data(), sign.size(), ecKey);
    return (ret == SUCCEED);
}
