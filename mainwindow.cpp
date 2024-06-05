#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QRandomGenerator>
#include<QMessageBox>
#include<QFileDialog>
#include<QRegularExpression>
#include<QtConcurrent/QtConcurrent>
#include <QDebug>
#include "SM4.h"
#include "SM3.h"
#include "SM2.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->pushButton,&QPushButton::clicked,[&](){
        QByteArray priKey, pubKey;
        //SM2 sm2;
        if(ui->comboBox->currentText()=="sm2p256v1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sm2p256v1);
        }
        else if(ui->comboBox->currentText()=="prime256v1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::prime256v1);
        }

        else if(ui->comboBox->currentText()=="secp256k1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::secp256k1);
        }
        else if(ui->comboBox->currentText()=="secp384r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::secp384r1);
        }
        else if(ui->comboBox->currentText()=="secp521r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::secp521r1);
        }

        else if(ui->comboBox->currentText()=="sect233k1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect233k1);
        }
        else if(ui->comboBox->currentText()=="sect233r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect233r1);
        }
        else if(ui->comboBox->currentText()=="sect409k1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect409k1);
        }
        else if(ui->comboBox->currentText()=="sect409r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect409r1);
        }
        else if(ui->comboBox->currentText()=="sect571k1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect571k1);
        }
        else if(ui->comboBox->currentText()=="sect571r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::sect571r1);
        }

        else if(ui->comboBox->currentText()=="brainpoolP256r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP256r1);
        }
        else if(ui->comboBox->currentText()=="brainpoolP256t1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP256t1);
        }
        else if(ui->comboBox->currentText()=="brainpoolP384r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP384r1);
        }
        else if(ui->comboBox->currentText()=="brainpoolP384t1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP384t1);
        }
        else if(ui->comboBox->currentText()=="brainpoolP512r1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP512r1);
        }
        else if(ui->comboBox->currentText()=="brainpoolP512t1")
        {
            SM2::generateKeyPair(priKey, pubKey,CurveName::brainpoolP512t1);
        }


        else
        {
            SM2::generateKeyPair(priKey, pubKey);
        }


        ui->plainTextEdit->setPlainText(priKey);
        ui->plainTextEdit_2->setPlainText(pubKey);
    });
    connect(ui->pushButton_2,&QPushButton::clicked,[&](){
        //        QDir dir;
        //        dir.mkdir("密钥");
        if(ui->plainTextEdit->toPlainText().isEmpty())
        {
            return ;
        }
        //QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./密钥/私钥.pem", "密钥文件(*.pem)");
        QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./私钥.pem", "密钥文件(*.pem);;任意文本文件(*.*)");
        //QFile file("./rsa_private_key.pem");
        if(fileName.isEmpty())
        {
            return ;
        }
        QFile file(fileName);
        if(file.open(QIODevice::WriteOnly))
        {
            QString data=ui->plainTextEdit->toPlainText();
            file.write(data.toUtf8());
            file.close();
            QMessageBox::information(this, "提示信息", "保存成功！！");
        }
    });
    connect(ui->pushButton_3,&QPushButton::clicked,[&](){
        //        QDir dir;
        //        dir.mkdir("密钥");
        if(ui->plainTextEdit_2->toPlainText().isEmpty())
        {
            return ;
        }
        //QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./密钥/公钥.pem", "密钥文件(*.pem)");
        QString fileName = QFileDialog::getSaveFileName(this, "保存私钥文件", "./公钥.pem", "密钥文件(*.pem);;任意文本文件(*.*)");
        //QFile file("./rsa_private_key.pem");
        if(fileName.isEmpty())
        {
            return ;
        }
        QFile file(fileName);
        if(file.open(QIODevice::WriteOnly))
        {
            QString data=ui->plainTextEdit_2->toPlainText();
            file.write(data.toUtf8());
            file.close();
            QMessageBox::information(this, "提示信息", "保存成功！！");
        }
    });

    connect(ui->pushButton_4,&QPushButton::clicked,[&](){

        QString str=QFileDialog::getOpenFileName(this,"读取私钥文件", "./密钥/", "密钥文件(*.pem);;任意文本文件(*.*)");
        if(str.isEmpty())
        {
            return;
        }
        QFile file(str);
        if(file.open(QIODevice::ReadOnly|QIODevice::Text))
        {
            QString pub=file.readAll();
            ui->plainTextEdit->setPlainText(pub);
            file.close();
        }
    });

    connect(ui->pushButton_5,&QPushButton::clicked,[&](){

        QString str=QFileDialog::getOpenFileName(this,"读取公钥文件", "./密钥/", "密钥文件(*.pem);;任意文本文件(*.*)");
        if(str.isEmpty())
        {
            return;
        }
        QFile file(str);
        if(file.open(QIODevice::ReadOnly|QIODevice::Text))
        {
            QString pub=file.readAll();
            ui->plainTextEdit_2->setPlainText(pub);
            file.close();
        }
    });

    connect(ui->pushButton_6,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_2->toPlainText().isEmpty() || ui->plainTextEdit_3->toPlainText().isEmpty())
        {
            return;
        }
        QByteArray pubkey=ui->plainTextEdit_2->toPlainText().toUtf8();
        QByteArray in=ui->plainTextEdit_3->toPlainText().toUtf8();
        ui->plainTextEdit_4->setPlainText(SM2::encrypt(in,pubkey));

//        QByteArray out;
//        SM2::encrypt(in,out,pubkey);
//        ui->plainTextEdit_4->setPlainText(out.toBase64());

//        QByteArray outf;
//        QFile file("明文.txt");
//        if(file.open(QIODevice::ReadOnly))
//        {
//            QByteArray inf= file.readAll();
//            outf=SM2::encrypt(inf,pubkey);
//            file.close();
//        }
//        QFile file2("密文.txt");
//        if(file2.open(QIODevice::WriteOnly))
//        {
//            file2.write(outf.toBase64());
//            file2.close();
//        }
    });

    connect(ui->pushButton_7,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit->toPlainText().isEmpty() || ui->plainTextEdit_4->toPlainText().isEmpty())
        {
            return;
        }

        QByteArray prikey=ui->plainTextEdit->toPlainText().toUtf8();
        QByteArray in=ui->plainTextEdit_4->toPlainText().toUtf8();
        ui->plainTextEdit_3->setPlainText(SM2::decrypt(in,prikey));

//        QByteArray in=QByteArray::fromBase64(ui->plainTextEdit_4->toPlainText().toUtf8());
//        QByteArray out;
//        SM2::decrypt(in,out,prikey);
//        ui->plainTextEdit_3->setPlainText(out);

//        QByteArray outf;
//        QFile file("密文.txt");
//        if(file.open(QIODevice::ReadOnly))
//        {
//            QByteArray inf= QByteArray::fromBase64(file.readAll());

//            outf= SM2::decrypt(inf,prikey);
//            file.close();
//        }
//        QFile file2("明文2.txt");
//        if(file2.open(QIODevice::WriteOnly))
//        {
//            file2.write(outf);
//            file2.close();
//        }

    });

    connect(ui->pushButton_8,&QPushButton::clicked,[&](){
        //ui->plainTextEdit_5->setPlainText(generateHexData(32));
        //ui->plainTextEdit_6->setPlainText(generateHexData(32));
        QByteArray key,iv;
        SM4().generateKey(key,iv);

        ui->plainTextEdit_5->setPlainText(key.toHex());
        ui->plainTextEdit_6->setPlainText(iv.toHex());

    });

    connect(ui->pushButton_9,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_5->toPlainText().isEmpty()||ui->plainTextEdit_3->toPlainText().isEmpty())
        {
            return;
        }
        QString str=ui->plainTextEdit_5->toPlainText();
        QRegularExpression hexPattern(R"(\b(0x|0X)?[0-9a-fA-F]+\b)");

        // 使用正则表达式检查字符串
        QRegularExpressionMatch match = hexPattern.match(str);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOk=( match.hasMatch() && match.capturedLength() == str.length());
        if (conversionOk && str.size() == 32)
        {
            QByteArray key=QByteArray::fromHex(str.toUtf8());
            QByteArray in=ui->plainTextEdit_3->toPlainText().toUtf8();
            QByteArray out;
            SM4().ecb_encrypt(in,out,key,true);
            ui->plainTextEdit_4->setPlainText(out.toBase64());
        }
        else
        {
            QMessageBox::information(this, "提示信息", "请使用随机生成的密钥\n或使用32个16进制的数！！");
        }

    });
    connect(ui->pushButton_10,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit->toPlainText().isEmpty())
        {
            return;
        }
        QByteArray prikey=ui->plainTextEdit->toPlainText().toUtf8();
        QByteArray pubkey;
        SM2::generateKeyPUBPair(prikey,pubkey);
        ui->plainTextEdit_2->setPlainText(pubkey);

    });

    connect(ui->pushButton_14,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_3->toPlainText().isEmpty())
        {
            return;
        }
        QByteArray plainText = ui->plainTextEdit_3->toPlainText().toUtf8();
        ui->plainTextEdit_4->setPlainText(SM3().digest(plainText).toHex().toUpper());

    });

    connect(ui->pushButton_12,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_5->toPlainText().isEmpty()||ui->plainTextEdit_4->toPlainText().isEmpty())
        {
            return;
        }
        QString str=ui->plainTextEdit_5->toPlainText();
        QRegularExpression hexPattern(R"(\b(0x|0X)?[0-9a-fA-F]+\b)");

        // 使用正则表达式检查字符串
        QRegularExpressionMatch match = hexPattern.match(str);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOk=( match.hasMatch() && match.capturedLength() == str.length());
        if (conversionOk && str.size() == 32)
        {
            QByteArray key=QByteArray::fromHex(str.toUtf8());
            QByteArray in=QByteArray::fromBase64(ui->plainTextEdit_4->toPlainText().toUtf8());
            QByteArray out;
            SM4().ecb_encrypt(in,out,key,false);
            ui->plainTextEdit_3->setPlainText(out);
        }
        else
        {
            QMessageBox::information(this, "提示信息", "请使用随机生成的密钥\n或使用32个16进制的数！！");
        }

    });
    connect(ui->pushButton_11,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_5->toPlainText().isEmpty()||ui->plainTextEdit_3->toPlainText().isEmpty()
                ||ui->plainTextEdit_6->toPlainText().isEmpty())
        {
            return;
        }
        QString str=ui->plainTextEdit_5->toPlainText();
        QRegularExpression hexPattern(R"(\b(0x|0X)?[0-9a-fA-F]+\b)");

        // 使用正则表达式检查字符串
        QRegularExpressionMatch match = hexPattern.match(str);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOk=( match.hasMatch() && match.capturedLength() == str.length());

        QString striv=ui->plainTextEdit_6->toPlainText();

        // 使用正则表达式检查字符串
        match = hexPattern.match(striv);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOkiv=( match.hasMatch() && match.capturedLength() == striv.length());
        if (conversionOk && str.size() == 32 &&conversionOkiv&&striv.size()==32)
        {
            QByteArray key=QByteArray::fromHex(str.toUtf8());
            QByteArray in=ui->plainTextEdit_3->toPlainText().toUtf8();
            QByteArray iv=QByteArray::fromHex(striv.toUtf8());
            QByteArray out;
            SM4().cfb128_encrypt(in,out,key,iv,true);
            ui->plainTextEdit_4->setPlainText(out.toBase64());
        }
        else
        {
            QMessageBox::information(this, "提示信息", "请使用随机生成的密钥\n或使用32个16进制的数！！");
        }

    });
    connect(ui->pushButton_13,&QPushButton::clicked,[&](){

        if (ui->plainTextEdit_5->toPlainText().isEmpty()||ui->plainTextEdit_4->toPlainText().isEmpty()
                ||ui->plainTextEdit_6->toPlainText().isEmpty())
        {
            return;
        }
        QString str=ui->plainTextEdit_5->toPlainText();
        QRegularExpression hexPattern(R"(\b(0x|0X)?[0-9a-fA-F]+\b)");

        // 使用正则表达式检查字符串
        QRegularExpressionMatch match = hexPattern.match(str);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOk=( match.hasMatch() && match.capturedLength() == str.length());

        QString striv=ui->plainTextEdit_6->toPlainText();

        // 使用正则表达式检查字符串
        match = hexPattern.match(striv);

        // 如果整个字符串都被匹配，则返回true
        // 注意：这里我们使用match.capturedLength() == hexString.length()来确保整个字符串都是有效的16进制数
        bool conversionOkiv=( match.hasMatch() && match.capturedLength() == striv.length());
        if (conversionOk && str.size() == 32 &&conversionOkiv &&striv.size()==32)
        {
            QByteArray key=QByteArray::fromHex(str.toUtf8());
            QByteArray in=QByteArray::fromBase64(ui->plainTextEdit_4->toPlainText().toUtf8());
            QByteArray iv=QByteArray::fromHex(striv.toUtf8());
            QByteArray out;
            SM4().cfb128_encrypt(in,out,key,iv,false);
            ui->plainTextEdit_3->setPlainText(out);
        }
        else
        {
            QMessageBox::information(this, "提示信息", "请使用随机生成的密钥\n或使用32个16进制的数！！");
        }

    });

//    connect(ui->pushButton_15,&QPushButton::clicked,[&](){

//        if (ui->plainTextEdit->toPlainText().isEmpty() || ui->plainTextEdit_3->toPlainText().isEmpty())
//        {
//            return;
//        }
//        QByteArray prikey=ui->plainTextEdit->toPlainText().toUtf8();
//        QByteArray in=ui->plainTextEdit_3->toPlainText().toUtf8();
//        QByteArray out;
//        SM2::encryptpri(in,out,prikey);
//        ui->plainTextEdit_4->setPlainText(out.toBase64());

//    });
//    connect(ui->pushButton_16,&QPushButton::clicked,[&](){

//        if (ui->plainTextEdit_2->toPlainText().isEmpty() || ui->plainTextEdit_4->toPlainText().isEmpty())
//        {
//            return;
//        }
//        QByteArray pubkey=ui->plainTextEdit_2->toPlainText().toUtf8();
//        QByteArray in=QByteArray::fromBase64(ui->plainTextEdit_4->toPlainText().toUtf8());
//        QByteArray out;
//        SM2::decryptpub(in,out,pubkey);
//        ui->plainTextEdit_3->setPlainText(out);

//    });

//    QByteArray prikey;
//    QByteArray pubkey;
//    SM2::generateKeyPair(prikey,pubkey);
//    QByteArray digest="aaaaaaaa";
//    QByteArray sign;
//    qDebug()<<digest;
//    SM2::sign(digest,sign,prikey);
//    qDebug()<<sign;
//    QByteArray out;
//    //SM2::decryptpub(sign,out,pubkey);
//    qDebug()<<SM2::verify(digest,sign,pubkey);
    //qDebug()<<out;


}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::generateHexData(int length)
{
    QString hexData;
    for (int i = 0; i < length; i++) {
        int randomNumber = QRandomGenerator::global()->bounded(256);
        QString hexString = QString::number(randomNumber, 16);
        hexString = hexString.toUpper();
        if (hexString.length() == 1) {
            hexString.prepend('0');
        }
        hexData.append(hexString);
    }
    return hexData;
}





