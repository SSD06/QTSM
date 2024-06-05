#ifndef SM3_H
#define SM3_H

#include <QByteArray>

struct evp_md_ctx_st;
typedef struct evp_md_ctx_st EVP_MD_CTX;

class  SM3
{
public:
    SM3();
    ~SM3();

    // 计算一段数据的摘要信息
    QByteArray digest(const QByteArray& data);

private:
    EVP_MD_CTX *ctx;
};

#endif // SM3_H
