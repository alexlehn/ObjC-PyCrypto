ObjC-PyCrypto
=============

Port of the [PyCrypto](http://www.pycrypto.org/ "PyCrypto") AES Cipher (only CFB Mode) to ObjC to support encryption/descryption between Python and Objective-C (and Java) without the hassle of using CommonCrypto or OpenSSL


Importand
=============

This library does currently only support AES in CFB mode and is testet agains PyCrypto (AES.MODE_CFB) and Java's BouncyCastle (AES/CFB8/NoPadding)


ObjC-PyCrypto:

    TBD

python code tested:

    IV = '0' * 16
    cipher = AES.new(mySecret, AES.MODE_CFB, IV)


Java code tested:

    byte[] IV = new byte[16];
    for (int i = 0; i < IV; i++)
        IV[i] = (byte) i;

    IvParameterSpec iv = new IvParameterSpec(IV);
    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
    cipher.init(mode, mySecret, iv);