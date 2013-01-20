//
//  Created by Alexander Lehnert on 04.03.12.
//  Copyright 2011 Alexander Lehnert
//

#import <zlib.h>


@interface AESCryptoHelper : NSObject
{
@private
    NSString *_key;
    NSString *_IV;
    int _mode;
}

- (id)initWithKey:(NSString*)inKey;
- (id)initWithKey:(NSString*)inKey mode:(int)inMode;
- (id)initWithKey:(NSString*)inKey mode:(int)inMode usingIV:(NSString*)inIV;

/**
 @abstract Encrypt the given PlainText (HEX String) by using a CRC32 checksum
 from decrypted text

 @param PlainText to encrypt

 @return cipherText as HEX String
*/
-(NSString *)encryptPlainText:(NSString *)plainText;

/**
 @abstract Encrypt the given PlainText (HEX String) by optionaly using a CRC32 checksum
 from decrypted text
 
 @discussion The encrypted plaintext must contain a leading CRC32 checksum sepertaed by ':'. An example form is 'myEncryptedText:1234'

 @param PlainText to encrypt
 @param useCRC32 determinate if CRC32 should be shecked

 @return cipherText as HEX String
*/
-(NSString *)encryptPlainText:(NSString *)plainText usingCRCR32:(BOOL)useCRC32;

/**
 @abstract Decrypt the given CipherText (HEX String) by using a CRC32 checksum from
 decrypted text

 @param CipherText to decrypt

 @return plainText encrypted
*/
-(NSString *)decryptCipherText:(NSString *)cipherText;

/**
 @abstract Decrypt the given CipherText (HEX String) by optional using a CRC32 checksum
 from decrypted text

 @discussion The descrypted text contain a leading CRC32 checksum sepertaed by ':'. An example form is 'myEncryptedText:1234' result in some descrypted text
 
 @param CipherText to decrypt
 @param useCRC32 determinate if CRC32 should be apllyed

 @return plainText encrypted
*/
-(NSString *)decryptCipherText:(NSString *)cipherText usingCRC32:(BOOL)useCRC32;

/**
 @abstract Build a CRC32 checksum for the given text

 @param Text to calculate CRC32 from

 @return CRC32Checksum
*/
-(uLong)CRC32ForString:(NSString *)text;

/**
 @abstract Convert the given plain String to his HEX String representation

 @param PlainString to convert

 @return HEXString
*/
-(NSString *)convertStringToHex:(NSString *)str;

/**
 @abstract Convert the given Data to a HEX String representation

 @param PlainString data

 @return HEXString
*/
- (NSString *)convertDataToHEXString:(NSData *)data;

/**
 @abstract Convert the given HEX String to his Plain String representation

 @param HEXString to convert

 @return plainString
*/
-(NSString *)stringFromHexToStringConversion:(NSString *)hex;

/**
 @abstract Convert the given HEX String to his Plain Byte representation representation

 @param HEXString to convert

 @return plainBytes
*/
-(NSData *)dataFromHexToStringConversion:(NSString *)hex;

@end