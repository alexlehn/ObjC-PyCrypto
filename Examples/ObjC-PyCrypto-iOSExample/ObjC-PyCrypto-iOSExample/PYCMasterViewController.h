//
//  PYCMasterViewController.h
//  ObjC-PyCrypto-iOSExample
//
//  Created by Alexander Lehnert on 20.01.13.
//  Copyright (c) 2013 Alexander Lehnert. All rights reserved.
//

#import <UIKit/UIKit.h>

@class PYCDetailViewController;

@interface PYCMasterViewController : UITableViewController

@property (strong, nonatomic) PYCDetailViewController *detailViewController;

@end
