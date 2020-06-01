//
//  RNNativeFetch.m
//  medipass
//
//  Created by Paul Wong on 13/10/16.
//  Copyright © 2016 Localz. All rights reserved.
//

#import "RNPinch.h"
#import "RCTBridge.h"

@interface RNPinchException : NSException
@end
@implementation RNPinchException
@end

// private delegate for verifying certs
@interface NSURLSessionSSLPinningDelegate:NSObject <NSURLSessionDelegate>
{
    NSMutableURLRequest *reactRequest;
    NSDictionary *jsonRes;
    NSString *cookie;

}
@property (nonatomic,strong) NSURLSession* session;
@property (nonatomic,strong) NSMutableData *receivedData;
@property (nonatomic, strong) NSHTTPURLResponse* httpURLResponse;
@property (nonatomic,assign,getter=isExecuting) BOOL executing;
@property (nonatomic,assign,getter=isFinished) BOOL finished;

- (id)initWithCertNames:(NSArray<NSString *> *)certNames;

@property (nonatomic, strong) NSArray<NSString *> *certNames;

@end

@implementation NSURLSessionSSLPinningDelegate

- (id)initWithCertNames:(NSArray<NSString *> *)certNames {
    if (self = [super init]) {
        _certNames = certNames;
    }
    return self;
}

- (NSArray *)pinnedCertificateData {
    NSMutableArray *localCertData = [NSMutableArray array];
    for (NSString* certName in self.certNames) {
        NSString *cerPath;
        if([[certName substringToIndex:1] isEqualToString:@"/"]){
            cerPath = [NSHomeDirectory() stringByAppendingFormat:@"%@",certName];
        } else {
            cerPath = [[NSBundle mainBundle] pathForResource:certName ofType:@"cer"];
        }
        if (cerPath == nil) {
            @throw [[RNPinchException alloc]
                    initWithName:@"CertificateError"
                    reason:@"Can not load certicate given, check it's in the app resources."
                    userInfo:nil];
        }
        [localCertData addObject:[NSData dataWithContentsOfFile:cerPath]];
    }
    
    NSMutableArray *pinnedCertificates = [NSMutableArray array];
    for (NSData *certificateData in localCertData) {
        [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
    }
    return pinnedCertificates;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    
    if ([[[challenge protectionSpace] authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSString *domain = challenge.protectionSpace.host;
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
        
        NSArray *policies = @[(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
        
        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);
        // setup
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.pinnedCertificateData);
        SecTrustResultType result;
        
        // evaluate
        OSStatus errorCode = SecTrustEvaluate(serverTrust, &result);
        
        BOOL evaluatesAsTrusted = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
        if (errorCode == errSecSuccess && evaluatesAsTrusted) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else {
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, NULL);
        }
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}

@end

@interface RNPinch()

@property (nonatomic, strong) NSURLSessionConfiguration *sessionConfig;

@end

@implementation RNPinch
RCT_EXPORT_MODULE();

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        self.sessionConfig.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    }
    return self;
}

RCT_EXPORT_METHOD(fetch:(NSString *)url obj:(NSDictionary *)obj callback:(RCTResponseSenderBlock)callback) {
    NSURL *u = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:u];
    
    NSURLSession *session;
    if (obj) {
        if (obj[@"method"]) {
            [request setHTTPMethod:obj[@"method"]];
        }
        if (obj[@"timeoutInterval"]) {
            [request setTimeoutInterval:[obj[@"timeoutInterval"] doubleValue] / 1000];
        }
        if (obj[@"headers"] && [obj[@"headers"] isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary *m = [obj[@"headers"] mutableCopy];
            for (NSString *key in [m allKeys]) {
                if (![m[key] isKindOfClass:[NSString class]]) {
                    m[key] = [m[key] stringValue];
                }
            }
            [request setAllHTTPHeaderFields:m];
        }
        if (obj[@"body"]) {
            NSData *data = [obj[@"body"] dataUsingEncoding:NSUTF8StringEncoding];
            [request setHTTPBody:data];
        }
    }
    if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"cert"]) {
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:@[obj[@"sslPinning"][@"cert"]]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else if (obj && obj[@"sslPinning"] && obj[@"sslPinning"][@"certs"]) {
        // load all certs
        NSURLSessionSSLPinningDelegate *delegate = [[NSURLSessionSSLPinningDelegate alloc] initWithCertNames:obj[@"sslPinning"][@"certs"]];
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig delegate:delegate delegateQueue:[NSOperationQueue mainQueue]];
    } else {
        session = [NSURLSession sessionWithConfiguration:self.sessionConfig];
    }
    
    __block NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (!error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                NSHTTPURLResponse *httpResp = (NSHTTPURLResponse*) response;
                NSInteger statusCode = httpResp.statusCode;
                NSString *bodyString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                NSString *statusText = [NSHTTPURLResponse localizedStringForStatusCode:httpResp.statusCode];
                
                NSDictionary *res = @{
                    @"status": @(statusCode),
                    @"headers": httpResp.allHeaderFields,
                    @"bodyString": bodyString,
                    @"statusText": statusText
                };
                callback(@[[NSNull null], res]);
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                callback(@[@{@"message":error.localizedDescription}, [NSNull null]]);
            });
        }
    }];
    
    [dataTask resume];
}


/* Redirect Handlling Request*/

-(IBAction)redirectRequest
{
    NSString *urlString = @"https://pprd.us.auth.kamereon.org/kauth/oauth2/n-nissan-na-pprd/authorize?response_type=token%20id_token&scope=openid%20profile%20vehicles&redirect_uri=https://sxm-kauth.com&client_id=n-nissan-na-sxm-pprd&state=KJWJGMlekfjhqfF&nonce=Fkjlqmkfoq";
    
    cookie = @"kauthSession=AQIC5wM2LY4SfcyWpuyVThmnMV0sae_i3h7Ev1uOYPk4wZo.*AAJTSQACMDIAAlNLABI3MDYxNTcyMTUwMjM0OTI1MDcAAlMxAAIwMw..*";
    [self redirectRequest:urlString cookies:cookie placeHolder:nil];
}

-(void) responseHeaderResult
{
    NSLog(@"Header Info %@", jsonRes);
}

-(void) failedResponse:(NSString *)errorString
{
    NSLog(@"Header Info", errorString);
}



- (void)redirectRequest:(NSString *) urlString  cookies:(NSString *)cookies placeHolder:(NSDictionary *)headerFiledWithKey
{
    if (!urlString)
    {
        NSLog(@"[HTTPRequest] please fill url field before calling performRequest");
        [self failedResponse:@"please fill url field before calling performRequest"];
        return;
    };
    
    NSString * requestString = [NSString stringWithString: urlString];
    
    reactRequest = [[NSMutableURLRequest alloc] init] ;
    [reactRequest setURL:[NSURL URLWithString:requestString]];
    [reactRequest setHTTPMethod: @"GET"];
    [reactRequest setTimeoutInterval: 45];
    [reactRequest setValue: cookies forHTTPHeaderField: @"Cookie"];
    
    for (NSString * key in headerFiledWithKey)
    {
        [reactRequest setValue: [headerFiledWithKey valueForKey: key] forHTTPHeaderField: key];
        
    }
    
    NSLog(@"Send http request to URL: %@", urlString);
    //  NSLog(@"Request Header are: %@", [theRequest allHTTPHeaderFields]);
    
#ifdef _DEBUG
    for (id key in [theRequest allHTTPHeaderFields])
    {
        NSLog(@"header line: %@ = %@", key, [[theRequest allHTTPHeaderFields] valueForKey:key]);
    }
#endif //_DEBUG
    
    //        if(postBody)
    //        {
    //            [theRequest setHTTPBody: postBody];
    //        }
    
    //reactConnection = [[NSURLConnection alloc] initWithRequest:reactRequest delegate:self startImmediately: YES];
    
    //reactConnection = [NSURLSession sessionWithConfiguration:<#(nonnull NSURLSessionConfiguration *)#> delegate:self delegateQueue:<#(nullable NSOperationQueue *)#>]
    self.executing = YES;
    
    NSURLSessionConfiguration* config = [NSURLSessionConfiguration defaultSessionConfiguration];
    config.timeoutIntervalForRequest = 45;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    self.session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    [[self.session dataTaskWithRequest:reactRequest] resume];
    if ( self.session)
    {
        if (_receivedData == nil)
            _receivedData = [NSMutableData data] ;
    }
    else
    {
        NSLog(@"Network Error");
    }
}




- (void)cancel {
    [self.session invalidateAndCancel];
    [self finishOperation];
}

- (void)finishOperation {
    [self.session invalidateAndCancel];
    if (self.isExecuting) {
        self.executing = NO;
    }
    if (!self.isFinished) {
        self.finished = YES;
    }
}

- (BOOL)isConcurrent {
    return YES;
}

- (void)setExecuting:(BOOL)executing {
    [self willChangeValueForKey:@"isExecuting"];
    _executing = executing;
    [self didChangeValueForKey:@"isExecuting"];
}

- (void)setFinished:(BOOL)finished {
    [self willChangeValueForKey:@"isFinished"];
    _finished = finished;
    [self didChangeValueForKey:@"isFinished"];
}

#pragma mark NSURLSessionTaskDelegate methods

-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler {
    NSLog(@"Network Test current thread %@", [NSThread currentThread]);
    NSLog(@"willPerformHTTPRedirection");
    NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *) response;
    int statusCode = [httpResponse statusCode];
    //NSLog (@"HTTP status %d %@", statusCode, redirectResponse);
    NSDictionary *results    = (NSDictionary *)response;
    NSLog(@"Network Class %@ %ld", results, statusCode);
    
    if ([httpResponse respondsToSelector:@selector(allHeaderFields)] && statusCode == 302) {
        jsonRes = [httpResponse allHeaderFields];
        NSLog(@" Data get from server %@", [jsonRes description]);
        [self responseHeaderResult];
    }
    completionHandler(nil);
}

-(void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveResponse:(NSURLResponse *)response completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler {
    
    NSLog(@"Network Test current thread %@", [NSThread currentThread]);
    NSLog(@"didReceiveResponse");
    completionHandler(NSURLSessionResponseAllow);
    self.httpURLResponse = (NSHTTPURLResponse*)response;
}

-(void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    NSLog(@"Network Test current thread %@", [NSThread currentThread]);
    if (!self.receivedData) {
        self.receivedData = [[NSMutableData alloc] init];
    }
    NSLog(@"didReceiveData");
    [self.receivedData appendData:data];
}

-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    NSLog(@"Network Test current thread %@", [NSThread currentThread]);
    NSLog(@"didCompleteWithError");
    [self finishOperation];
}

@end
