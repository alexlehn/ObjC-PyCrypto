//
//  PYCAppDelegate.h
//  ObjC-PyCrypto-CocoaExample
//
//  Created by Alexander Lehnert on 20.01.13.
//  Copyright (c) 2013 Boinx Software. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface PYCAppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSTextField *inputTextFieldEncode;
@property (assign) IBOutlet NSTextField *outputTextFieldEncode;
@property (assign) IBOutlet NSTextField *inputTextFieldDecode;
@property (assign) IBOutlet NSTextField *outputTextFieldDecode;

@end
