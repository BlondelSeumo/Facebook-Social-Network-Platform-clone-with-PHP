//
//  ViewController.m
//  webApp
//
//  Created by ali fouad srhan on 4/25/16.
//  Copyright (c) 2016 ali fouad srhan. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    webURL=@"http://demo.sngine.com";
    
    NSURL *url = [NSURL URLWithString:webURL];
    NSURLRequest *requestObj = [NSURLRequest requestWithURL:url];
    [webView loadRequest:requestObj];
}
-(void) viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
}

-(void)webViewDidFinishLoad:(UIWebView *)webView
{
    [acitvityLoader stopAnimating];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
