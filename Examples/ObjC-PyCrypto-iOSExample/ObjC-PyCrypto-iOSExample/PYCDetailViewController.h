//
//  PYCDetailViewController.h
//  ObjC-PyCrypto-iOSExample
//
//  Created by Alexander Lehnert on 20.01.13.
//  Copyright (c) 2013 Alexander Lehnert. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface PYCDetailViewController : UIViewController <UISplitViewControllerDelegate>

@property (strong, nonatomic) id detailItem;

@property (strong, nonatomic) IBOutlet UILabel *detailDescriptionLabel;

@end
