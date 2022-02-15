//
//  ViewController.h
//  webApp
//
//  Created by ali fouad srhan on 4/25/16.
//  Copyright (c) 2016 ali fouad srhan. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController<UIWebViewDelegate>
{
    
    __weak IBOutlet UIActivityIndicatorView *acitvityLoader;
    __weak IBOutlet UIWebView *webView;
    NSString * webURL;
}


@end

