#-------------------------------------------------
#
# Project created by QtCreator 2020-06-17T11:06:04
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = openssl_test
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h \
    include/openssl/aes.h \
    include/openssl/md5.h \
    include/openssl/rsa.h

FORMS    += mainwindow.ui


unix:!macx: LIBS += -L$$PWD/lib/ -lcrypto

INCLUDEPATH += $$PWD/include
DEPENDPATH += $$PWD/include

unix:!macx: LIBS += -L$$PWD/lib/ -lcrypto

INCLUDEPATH += $$PWD/include
DEPENDPATH += $$PWD/include
