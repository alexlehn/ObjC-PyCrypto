//
//  Created by Alexander Lehnert on 04.03.12.
//  Copyright 2011 Alexander Lehnert
//


#import "AESCryptoHelper.h"
#import "AESCipher.h"


#define DEFAULT_IV @"0000000000000000"


#pragma mark - C utility functions

static const char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static const int byteMapLen = sizeof(byteMap);

// utility function to convert hex character representation to their nibble (4 bit) values
static uint8_t nibbleFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 255;
}

// Utility function to convert nibbles (4 bit values) into a hex character representation
static char nibbleToChar(uint8_t nibble)
{
	if(nibble < byteMapLen) return byteMap[nibble];
	return '*';
}


#pragma mark - Private interface

@interface AESCryptoHelper()

@property (nonatomic, retain) NSString *key;
@property (nonatomic, retain) NSString *IV;
@property (nonatomic, assign) int mode;

@end


#pragma mark - AESCryptoHelper implementation

@implementation AESCryptoHelper


#pragma mark - Lifecycle

-(id)init
{
    [self doesNotRecognizeSelector:_cmd];
    return self;
}


- (id)initWithKey:(NSString*)inKey
{
    return [self initWithKey:inKey mode:MODE_CFB];
}

- (id)initWithKey:(NSString*)inKey mode:(int)inMode
{
    return [self initWithKey:inKey mode:inMode usingIV:DEFAULT_IV];
}

- (id)initWithKey:(NSString*)inKey mode:(int)inMode usingIV:(NSString*)inIV
{
    self = [super init];
    if(self)
    {
        self.key = inKey;
        self.IV = inIV;
        self.mode = inMode;
    }
    return self;
}


- (void)dealloc
{
    [super dealloc];
}


#pragma mark - Cryptographic methods

-(NSString *)encryptPlainText:(NSString *)plainText
{
    return [self encryptPlainText:plainText usingCRCR32:YES];
}

-(NSString *)encryptPlainText:(NSString *)plainText usingCRCR32:(BOOL)useCRC32
{
	AESCipher const *cipher = [[AESCipher alloc] initWithMode: self.mode
                                                    keyString: self.key
                                                     ivString: self.IV];

	// let us append the CRC32 Checksum
    if (useCRC32) {
        uLong CRC32 = [self CRC32ForString:plainText];
		plainText = [NSString stringWithFormat:@"%@:%lu", plainText, CRC32];
    }

    NSData *plainData    = [plainText dataUsingEncoding:NSASCIIStringEncoding];
	NSData *cipherData   = [cipher encrypt:plainData];
	NSString *cipherText = [self convertDataToHEXString:cipherData];

    [cipher release];
    
	return cipherText;
}

-(NSString *)decryptCipherText:(NSString *)cipherText
{
    return [self decryptCipherText:cipherText usingCRC32:YES];
}

-(NSString *)decryptCipherText:(NSString *)cipherText usingCRC32:(BOOL)useCRC32
{

	AESCipher const *cipher = [[AESCipher alloc] initWithMode: self.mode
                                                    keyString: self.key
                                                     ivString: self.IV];

	NSData *cipherData  = [self dataFromHexToStringConversion:cipherText];
    NSData *plainData   = [cipher decrypt:cipherData];
	NSString *plainText = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];

	// let us check the CRC32 Checksum
    if (useCRC32)
    {
		// Detect last position of ':' and cut off from string
		long seperatorPosition = 0;
		for(long i=plainText.length-1; i>0; i--)
        {
			if([plainText characterAtIndex:i] == ':')
            {
				seperatorPosition = i;
				break;
			}
		}
		// unable to find seperator ':' or position invalid
		if (0==seperatorPosition || seperatorPosition >= plainText.length)
        {
            [plainText release];
            plainText = nil;
		}
        else
        {
            NSString *encryptedText = [plainText substringToIndex:seperatorPosition];
            NSString *crc32Checksum = [plainText substringFromIndex:seperatorPosition+1];

            // Check for Valid CRC32
            uLong CRC32 = [self CRC32ForString:encryptedText];
            
            [plainText release];
            plainText = nil;
            
            if (CRC32 == [crc32Checksum longLongValue])
            {
                plainText = [encryptedText copy];
            }
        }
	}
    [cipher release];
    
    return [plainText autorelease];
}


#pragma mark - HEX and CRC32 methods

-(uLong)CRC32ForString:(NSString *)text
{
    NSData *input = [text dataUsingEncoding:NSUTF8StringEncoding];

    uLong crcValue = crc32(0L, NULL, 0L);
    crcValue = crc32(crcValue, (const Bytef*)input.bytes, (uInt)input.length);
    return crcValue;
}

-(NSString *)convertStringToHex:(NSString *)str
{
    NSUInteger len = [str length];
    unichar *chars = malloc(len * sizeof(unichar));
    [str getCharacters:chars];

     NSMutableString *hexString = [[NSMutableString alloc] init];

     for(NSUInteger i = 0; i < len; i++ )
     {
        [hexString appendString:[NSString stringWithFormat:@"%x", chars[i]]];
     }
     free(chars);

     return [hexString autorelease];
}

-(NSString *)convertDataToHEXString:(NSData *)data
{
	NSMutableString *hexString = [[NSMutableString alloc] init];
	for(int i=0; i<data.length; i++)
    {
		char lower  = nibbleToChar(((uint8_t*)(data.bytes))[i] >> 4);
		char higher = nibbleToChar(((uint8_t*)(data.bytes))[i] & 0x0f);
		[hexString appendString:[NSString stringWithFormat:@"%c%c", lower, higher]];
	}
	return [hexString autorelease]; //[hexString copy];
}

-(NSString *)stringFromHexToStringConversion:(NSString *)hex
{
    NSData *data = [self dataFromHexToStringConversion:hex];
    return [NSString stringWithFormat:@"%s", data.bytes];
}

-(NSData *)dataFromHexToStringConversion:(NSString *)hex
{
    NSMutableData *stringData = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char *utf8 = (char*)[hex UTF8String];
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < [hex length] / 2; i++)
    {
        byte_chars[0] = utf8[i*2];
        byte_chars[1] = utf8[i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [stringData appendBytes:&whole_byte length:1];
    }

    unsigned char terminator = '\0';
    [stringData appendBytes:&terminator length:1];

    return [stringData autorelease];
}


#pragma mark - Accessors

@synthesize key = _key;
@synthesize IV = _IV;
@synthesize mode = _mode;

@end