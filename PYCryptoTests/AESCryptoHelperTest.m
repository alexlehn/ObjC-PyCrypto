//
//  Created by Alexander Lehnert on 04.03.12.
//  Copyright 2011 Alexander Lehnert
//

#import <SenTestingKit/SenTestingKit.h>

#import "AESCipher.h"
#import "AESCryptoHelper.h"
#import "JSONKit.h"

#define ENCRYPT 0
#define DECRYPT 1


#define StaticKey @"sl8!4q*&&v3v5lv_#@l3xyj3^akz9_4-"

/**
 * aes crypto
 */
#define CHECKSUM_JSON @"{\"array\": [{\"string\": \"inceptos\", \"crc\": 3172196726}, {\"string\": \"euismod\", \"crc\": 437301338}, {\"string\": \"dolor\", \"crc\": 3564541177}, {\"string\": \"condimentum\", \"crc\": 1350686522}, {\"string\": \"leo\", \"crc\": 2064320637}, {\"string\": \"quam\", \"crc\": 4011390301}, {\"string\": \"conubia\", \"crc\": 1638544229}, {\"string\": \"amet\", \"crc\": 2905816526}, {\"string\": \"a\", \"crc\": 3904355907}, {\"string\": \"sollicitudin\", \"crc\": 3254270797}, {\"string\": \"Mauris\", \"crc\": 3505519124}, {\"string\": \"Nunc\", \"crc\": 661662818}, {\"string\": \"some_email@irgendwo.ly\", \"crc\": 4200120226}]}"
// TODO: testAsHex -> values for non printable chars and ascii > 128
#define HEX_JSON @"{\"array\": [{\"string\": \"a1b3544d29e19fe16f45c5df45ab14\", \"hex\": \"613162333534346432396531396665313666343563356466343561623134\"}, {\"string\": \"some_email@irgendwo.ly\", \"hex\": \"736f6d655f656d61696c40697267656e64776f2e6c79\"}, {\"string\": \"0^9yy@r530l&nr%lvd*@juj#ncf8ua&xjcb1+%@eu^d&7+wznr\", \"hex\": \"305e39797940723533306c266e72256c76642a406a756a236e636638756126786a6362312b254065755e6426372b777a6e72\"}, {\"string\": \"sl8!4q*&&v3v5lv_#@l3xyj3^akz9_4-5w0s5qol(54f+p_n(m\", \"hex\": \"736c382134712a2626763376356c765f23406c3378796a335e616b7a395f342d3577307335716f6c283534662b705f6e286d\"}, {\"string\": \"&szlig;\", \"hex\": \"26737a6c69673b\"}]}"
#define ENCRYPT_WITHOUT_CHECKSUM_JSON @"{\"array\": [{\"string\": \"Mauris\", \"crypto\": \"982d6e184afa30657d0ff60f0c321c493c\"}, {\"string\": \"some_email@irgendwo.ly\", \"crypto\": \"a6d765a067f978926b64c8e88c6c95f5aa8ebbb420cdabf6c63857d8c223fd95f5\"}, {\"string\": \"sl8!4q*&&v3v5lv_#@l3xyj3^akz9_4-\", \"crypto\": \"a6d4e950c86cf18b326b11b4f483add7aba18d36ad0c771a5fb1488c57b11465e35ddb049e428121028fa5\"}]}"

@interface AESCryptoHelperTest : SenTestCase

-(void)doCFB8TestForDirection:(int)direction keyStr:(NSString*)keyStr ivStr:(NSString*)ivStr cipherData:(NSData*)cipherData plainData:(NSData*)plainData;

@end

@implementation AESCryptoHelperTest

-(void)testCRC32ForString
{    
    NSDictionary *JSON = [CHECKSUM_JSON objectFromJSONString];
    NSArray *checksums = [JSON objectForKey:@"array"];

    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:StaticKey] autorelease];

    for(NSDictionary *entry in checksums) {

		uLong crc = [[entry objectForKey:@"crc"] longLongValue];
        NSString *str = [entry objectForKey:@"string"];

        uLong newCRC = [cryptoHelper CRC32ForString:str];

        assertThatLongLong(newCRC, equalToLongLong(crc));
    }
}

-(void)testConvertStringToHEX
{
    NSDictionary *JSON = [HEX_JSON objectFromJSONString];
    NSArray *hexValues = [JSON objectForKey:@"array"];
    
    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:StaticKey] autorelease];

    for(NSDictionary *entry in hexValues) {

        NSString *str = [entry objectForKey:@"string"];
        NSString *hex = [entry objectForKey:@"hex"];

        NSString *newHex = [cryptoHelper convertStringToHex:str];

        assertThat(newHex, equalTo(hex));
    }
}

-(void)testConvertHexString
{
    NSDictionary *JSON = [HEX_JSON objectFromJSONString];
    NSArray *hexValues = [JSON objectForKey:@"array"];
    
    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:StaticKey] autorelease];

    for(NSDictionary *entry in hexValues) {

        NSString *str = [entry objectForKey:@"string"];
        NSString *hex = [entry objectForKey:@"hex"];

        NSString *newStr = [cryptoHelper stringFromHexToStringConversion:hex];

        assertThat(newStr, equalTo(str));
    }
}

-(void)testEncrypt
{
    NSDictionary *JSON = [ENCRYPT_WITHOUT_CHECKSUM_JSON objectFromJSONString];
    NSArray *hexValues = [JSON objectForKey:@"array"];
    
    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:StaticKey] autorelease];

    for(NSDictionary *entry in hexValues) {

        NSString *plainText  = [entry objectForKey:@"string"];
        NSString *cipherText = [entry objectForKey:@"crypto"];

        NSString *newCipherText = [cryptoHelper encryptPlainText:plainText];

		NSLog(@"Encrypting \n    Plain-Text: %@ \n   Cipher-Text: %@ \n      Expected: %@ \n ", plainText, newCipherText, cipherText);
		assertThat(newCipherText, equalTo(cipherText));
    }
}

-(void)testDecrypt
{
    NSDictionary *JSON = [ENCRYPT_WITHOUT_CHECKSUM_JSON objectFromJSONString];
    NSArray *hexValues = [JSON objectForKey:@"array"];
    
    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:StaticKey] autorelease];

    for(NSDictionary *entry in hexValues) {

        NSString *plainText  = [entry objectForKey:@"string"];
        NSString *cipherText = [entry objectForKey:@"crypto"];

        NSString *newPlainText = [cryptoHelper decryptCipherText:cipherText];

		NSLog(@"Decrypting \n    Cipher-Text: %@ \n     Plain-Text: %@ \n       Expected: %@ \n ", cipherText, newPlainText, plainText);
        assertThat(newPlainText, equalTo(plainText));
    }
}

-(void)testCFB8
{
    NSString *keyString    = StaticKey; // @"sl8!4q*&&v3v5lv_#@l3xyj3^akz9_4-"; //@"736c382134712a2626763376356c765f23406c3378796a335e616b7a395f342d";   // sl8!4q*&&v3v5lv_#@l3xyj3^akz9_4-
    NSString *ivString     = @"0000000000000000";                                                   // 0 * 16
    NSString *cipherString = @"a6d765a067f978926b64c8e88c6c95f5aa8ebbb420cdabf6c63857d8c223fd95f5"; // ¶◊e†g˘xíkd»Ëålïı™éª¥ Õ´ˆ∆8Wÿ¬#˝ïı
    //NSString *plainText    = @"736f6d655f656d61696c40697267656e64776f2e6c793a34323030313230323236"; // some_email@irgendwo.ly:4200120226
    NSString *plainText    = @"some_email@irgendwo.ly:4200120226";

    AESCryptoHelper *cryptoHelper = [[[AESCryptoHelper alloc] initWithKey:keyString] autorelease];
    NSData *cipherData = [cryptoHelper dataFromHexToStringConversion:cipherString];
    NSData *plainData  = [plainText dataUsingEncoding:NSUTF8StringEncoding];

    [self doCFB8TestForDirection:DECRYPT keyStr:keyString ivStr:ivString cipherData:cipherData plainData:plainData];
    [self doCFB8TestForDirection:ENCRYPT keyStr:keyString ivStr:ivString cipherData:cipherData plainData:plainData];
}

-(void)doCFB8TestForDirection:(int)direction keyStr:(NSString*)keyStr ivStr:(NSString*)ivStr cipherData:(NSData*)cipherData plainData:(NSData*)plainData;
{
    // ALGobject *alGobject = ALGnew(keyStr, ivStr, MODE_CFB);


    //NSString *plainText = [NSString stringWithFormat:@"%s", plainData.bytes];

    //NSLog(@"Data\n  KeyString: %@ \n   IVString: %@ \n CypherText: %s \n  PlainText: %s (%i) \n", keyStr, ivStr, cipherData.bytes, plainData.bytes, plainData.length);
    //printf("\n\n");

    AESCipher const *cipher = [[[AESCipher alloc] initWithMode:MODE_CFB keyString:keyStr ivString:ivStr] autorelease];

    NSData *result;
    if (direction == DECRYPT) {
        result = [cipher decrypt:cipherData];
		
		NSString const *resultText = [[[NSString alloc] initWithData:result    encoding:NSUTF8StringEncoding] autorelease];
		NSString const *plainText  = [[[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding] autorelease];

		NSLog(@"Decrypting DONE \n   Result: %@ \n Expected: %@ \n ", resultText, plainText);
        assertThat(resultText, equalTo(plainText));
    } else {
        result = [cipher encrypt:plainData];

		NSString const *cipherText = [[[NSString alloc] initWithFormat:@"%s", cipherData.bytes] autorelease];
		NSString const *resultText  = [[[NSString alloc] initWithFormat:@"%s", result.bytes] autorelease];

        NSLog(@"Encrypting DONE \n   Result: %@ \n Expected: %@ \n ", cipherText, resultText);
        assertThat(resultText, equalTo(cipherText));
    }
}

@end