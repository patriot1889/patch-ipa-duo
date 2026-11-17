// Simulator host for scene.m. Link both files into this app; no mixer IPA needed.
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

@interface MixPadSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

static NSMutableArray<NSDictionary *> *SQChecks;
static NSUInteger SQOriginalInitializations;
static NSUInteger SQOriginalLayouts;
static BOOL SQFinished;

static BOOL SQRectEqual(CGRect lhs, CGRect rhs) {
    return lhs.origin.x == rhs.origin.x && lhs.origin.y == rhs.origin.y &&
        lhs.size.width == rhs.size.width && lhs.size.height == rhs.size.height;
}

static void SQCheck(NSString *name, BOOL passed) {
    if (!SQChecks) SQChecks = [NSMutableArray array];
    [SQChecks addObject:@{@"name": name, @"passed": @(passed)}];
    NSLog(@"SQ adapter check %@: %@", passed ? @"PASS" : @"FAIL", name);
}

static void SQWriteResult(NSException *exception) {
    if (SQFinished) return;
    SQFinished = YES;
    if (exception) SQCheck([NSString stringWithFormat:@"exception: %@: %@",
                           exception.name, exception.reason], NO);
    NSUInteger failures = 0;
    for (NSDictionary *check in SQChecks) if (![check[@"passed"] boolValue]) failures++;
    NSDictionary *result = @{@"status": failures ? @"failed" : @"passed",
        @"passed": @(failures == 0), @"failureCount": @(failures),
        @"checkCount": @(SQChecks.count), @"checks": SQChecks ?: @[],
        @"originalInitializations": @(SQOriginalInitializations),
        @"originalLayouts": @(SQOriginalLayouts),
        @"scope": @"Fake Qt classes with real UIKit scene; no mixer or IPA"};
    NSURL *documents = [NSFileManager.defaultManager
        URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].firstObject;
    NSURL *output = [documents URLByAppendingPathComponent:@"adapter-test-result.json"];
    NSError *error;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
    BOOL written = data && [data writeToURL:output options:NSDataWritingAtomic error:&error];
    NSLog(@"SQ adapter runtime tests: %@ (%lu checks, %lu failures). Result %@ %@",
        failures ? @"FAIL" : @"PASS", (unsigned long)SQChecks.count,
        (unsigned long)failures, output.path, written ? @"written" : error);
    // Stay alive so the caller can retrieve the result from the app container.
}

@interface QUIView : UIView
@property(nonatomic) BOOL reenterLayoutOnFrameChange;
@end
@implementation QUIView
- (void)setFrame:(CGRect)frame {
    BOOL changed = !SQRectEqual(self.frame, frame);
    [super setFrame:frame];
    if (changed && self.reenterLayoutOnFrameChange) [self.superview layoutSubviews];
}
@end

@interface QIOSDesktopManagerView : UIView
@property(nonatomic, strong) QUIView *mainContent;
@property(nonatomic, strong) QUIView *popupContent;
@property(nonatomic, strong) QUIView *hiddenContent;
@end
@implementation QIOSDesktopManagerView
- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _mainContent = [[QUIView alloc] initWithFrame:CGRectMake(0, 0, 320, 180)];
        _mainContent.backgroundColor = UIColor.systemBlueColor;
        _popupContent = [[QUIView alloc] initWithFrame:CGRectMake(23, 29, 40, 30)];
        _hiddenContent = [[QUIView alloc] initWithFrame:CGRectMake(0, 0, 4000, 3000)];
        _hiddenContent.hidden = YES;
        [self addSubview:_mainContent];
        [self addSubview:_popupContent];
        [self addSubview:_hiddenContent];
    }
    return self;
}
- (void)layoutSubviews {
    [super layoutSubviews];
    SQOriginalLayouts++;
    // Simulate Qt continuing to request its legacy fixed-size desktop content.
    self.mainContent.frame = CGRectMake(0, 0, 320, 180);
}
@end

@interface QIOSViewController : UIViewController
@property(nonatomic, strong) QIOSDesktopManagerView *desktop;
@property(nonatomic, weak) UIWindow *hideWindowDuringLoad;
@end
@implementation QIOSViewController
- (void)loadView {
    // A loaded, direct desktop root accidentally hid the adapter's launch gate.
    // Model Qt's deferred view creation and a desktop nested under a wrapper.
    UIView *root = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 320, 180)];
    self.desktop = [[QIOSDesktopManagerView alloc] initWithFrame:root.bounds];
    self.desktop.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [root addSubview:self.desktop];
    self.view = root;
    self.hideWindowDuringLoad.hidden = YES;
}
@end

@interface QUIWindow : UIWindow
@property(nonatomic) BOOL migratedWhileHidden;
@end
@implementation QUIWindow
- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) SQOriginalInitializations++;
    return self;
}
- (void)setWindowScene:(UIWindowScene *)scene {
    if (self.windowScene && self.windowScene != scene) self.migratedWhileHidden = self.hidden;
    [super setWindowScene:scene];
}
// Intentionally inherit setHidden:; the adapter must not swizzle UIWindow.
@end

static QUIWindow *SQCreateWindow(CGRect frame) {
    QUIWindow *window = [[QUIWindow alloc] initWithFrame:frame];
    QIOSViewController *controller = [QIOSViewController new];
    window.rootViewController = controller;
    return window;
}

@interface SQAdapterRuntimeAppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@interface SQAdapterRuntimeSceneDelegate : MixPadSceneDelegate
@property(nonatomic, strong) UISceneSession *testSession;
@property(nonatomic, strong) UISceneConnectionOptions *testOptions;
@property(nonatomic) BOOL didRun;
@end

@implementation SQAdapterRuntimeAppDelegate
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    @try {
        // Deliberately create/show Qt content before the actual scene connects.
        self.window = SQCreateWindow(CGRectMake(11, 13, 320, 180));
        [self.window setHidden:NO];
        SQCheck(@"early Qt window exists before scene connection", self.window.windowScene == nil);
    } @catch (NSException *exception) { SQWriteResult(exception); }
    return YES;
}
@end

@implementation SQAdapterRuntimeSceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
    options:(UISceneConnectionOptions *)connectionOptions {
    self.testSession = session;
    self.testOptions = connectionOptions;
    @try { [super scene:scene willConnectToSession:session options:connectionOptions]; }
    @catch (NSException *exception) { SQWriteResult(exception); }
}

- (void)sceneDidBecomeActive:(UIScene *)scene {
    [super sceneDidBecomeActive:scene];
    if (self.didRun || SQFinished) return;
    self.didRun = YES;
    // Run after scene activation; no arbitrary sleep or simulator orientation assumptions.
    dispatch_async(dispatch_get_main_queue(), ^{
        @try { [self runChecks:(UIWindowScene *)scene]; }
        @catch (NSException *exception) { SQWriteResult(exception); }
    });
}

- (void)runChecks:(UIWindowScene *)scene {
    SQCheck(@"all checks run on main thread", NSThread.isMainThread);
    SQAdapterRuntimeAppDelegate *app = (id)UIApplication.sharedApplication.delegate;
    UIWindow *early = app.window;
    SQCheck(@"early window attached to actual UIKit scene", early.windowScene == scene);
    SQCheck(@"scene delegate retains original Qt window", self.window == early);
    SQCheck(@"early window is visible and key", !early.hidden && early.isKeyWindow);
    SQCheck(@"original Qt initializer retained", SQOriginalInitializations == 1);
    SQCheck(@"inherited visibility hook is subclass-local",
        class_getInstanceMethod(QUIWindow.class, @selector(setHidden:)) !=
        class_getInstanceMethod(UIWindow.class, @selector(setHidden:)));

    SQCheck(@"scene attachment loads lazy Qt root", early.rootViewController.isViewLoaded);
    QIOSDesktopManagerView *desktop = ((QIOSViewController *)early.rootViewController).desktop;
    SQCheck(@"desktop can be nested below root view", desktop != early.rootViewController.view && desktop.superview == early.rootViewController.view);
    CGRect popupFrame = desktop.popupContent.frame;
    CGRect hiddenFrame = desktop.hiddenContent.frame;
    [desktop layoutSubviews];
    SQCheck(@"largest visible Qt content fills desktop", SQRectEqual(desktop.mainContent.frame, desktop.bounds));
    SQCheck(@"Qt popup child keeps geometry", SQRectEqual(desktop.popupContent.frame, popupFrame));
    SQCheck(@"hidden larger child keeps geometry", SQRectEqual(desktop.hiddenContent.frame, hiddenFrame));
    SQCheck(@"original Qt desktop layout executed", SQOriginalLayouts > 0);
    NSUInteger beforeReentry = SQOriginalLayouts;
    desktop.mainContent.reenterLayoutOnFrameChange = YES;
    [desktop layoutSubviews];
    desktop.mainContent.reenterLayoutOnFrameChange = NO;
    SQCheck(@"frame-driven recursive Qt layout is bounded", SQOriginalLayouts == beforeReentry + 1);
    SQCheck(@"recursive layout still fills main content", SQRectEqual(desktop.mainContent.frame, desktop.bounds));

    CGRect expected;
    early.frame = CGRectMake(7, 9, 123, 87);
    if (@available(iOS 26.0, *)) {
        expected = scene.effectiveGeometry.coordinateSpace.bounds;
        [self windowScene:scene didUpdateEffectiveGeometry:scene.effectiveGeometry];
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        expected = scene.coordinateSpace.bounds;
        [self windowScene:scene didUpdateCoordinateSpace:scene.coordinateSpace
            interfaceOrientation:UIInterfaceOrientationUnknown traitCollection:scene.traitCollection];
#pragma clang diagnostic pop
    }
    SQCheck(@"geometry callback restores scene window bounds", SQRectEqual(early.frame, expected));
    [desktop layoutSubviews];
    SQCheck(@"content follows updated scene geometry", SQRectEqual(desktop.mainContent.frame, desktop.bounds));

    QUIWindow *popupWindow = SQCreateWindow(CGRectMake(31, 37, 90, 70));
    popupWindow.windowLevel = UIWindowLevelAlert;
    CGRect popupWindowFrame = popupWindow.frame;
    [popupWindow setHidden:NO];
    SQCheck(@"Qt popup window is not attached as main", popupWindow.windowScene == nil && self.window == early);
    SQCheck(@"Qt popup window keeps frame", SQRectEqual(popupWindow.frame, popupWindowFrame));
    [popupWindow setHidden:YES];
    UIWindow *native = [[UIWindow alloc] initWithFrame:CGRectMake(41, 43, 80, 60)];
    CGRect nativeFrame = native.frame;
    [native setHidden:NO];
    SQCheck(@"native window remains outside bridge", native.windowScene == nil && SQRectEqual(native.frame, nativeFrame));
    [native setHidden:YES];

    [super sceneDidDisconnect:scene];
    SQCheck(@"disconnect clears scene delegate window", self.window == nil);
    SQCheck(@"disconnect detaches original Qt window", early.windowScene == nil);
    [super scene:scene willConnectToSession:self.testSession options:self.testOptions];
    SQCheck(@"reconnect reuses original Qt UI", self.window == early && early.windowScene == scene);

    [super sceneDidDisconnect:scene];
    // Remove the old content so a still-live test reference is not a candidate.
    early.hidden = YES;
    early.rootViewController = nil;
    app.window = nil;
    [super scene:scene willConnectToSession:self.testSession options:self.testOptions];
    SQCheck(@"empty connected scene gets no manufactured window", self.window == nil);
    QUIWindow *late = SQCreateWindow(CGRectMake(17, 19, 300, 170));
    [late setHidden:NO];
    SQCheck(@"late Qt window attaches after scene connection", self.window == late && late.windowScene == scene);
    SQCheck(@"late Qt window becomes visible and key", !late.hidden && late.isKeyWindow);
    QIOSDesktopManagerView *lateDesktop = ((QIOSViewController *)late.rootViewController).desktop;
    [lateDesktop layoutSubviews];
    SQCheck(@"late Qt main content fills desktop", SQRectEqual(lateDesktop.mainContent.frame, lateDesktop.bounds));

    // Ensure one queued attachment turn cannot revive an obsolete window.
    UIWindow *dialog = [[UIWindow alloc] initWithWindowScene:scene];
    dialog.rootViewController = [UIViewController new];
    dialog.windowLevel = UIWindowLevelAlert;
    [dialog makeKeyAndVisible];
    SQCheck(@"native scene dialog owns key focus", dialog.isKeyWindow);
    [super sceneDidBecomeActive:scene];
    SQCheck(@"scene activation preserves dialog key focus", dialog.isKeyWindow && !late.isKeyWindow);
    [late setHidden:NO];
    dispatch_async(dispatch_get_main_queue(), ^{
        SQCheck(@"queued retry preserves current late window", self.window == late && early.windowScene == nil);
        SQCheck(@"queued attachment preserves dialog key focus", dialog.isKeyWindow && !late.isKeyWindow);
        dialog.hidden = YES;
        [late setHidden:NO];
        SQCheck(@"main window can recover key focus after dialog closes", late.isKeyWindow);
        // Qt can create its window in a compatibility scene before UIKit
        // connects the application scene. Use a real UIScene instance to
        // exercise hide-before-migration instead of mocking windowScene.
        [self sceneDidDisconnect:scene];
        late.hidden = YES;
        late.rootViewController = nil;
        app.window = nil;
        UIWindowScene *compatibility = [[UIWindowScene alloc] initWithSession:self.testSession connectionOptions:self.testOptions];
        QUIWindow *migrating = SQCreateWindow(CGRectMake(0, 0, 320, 180));
        migrating.windowScene = compatibility;
        app.window = migrating;
        migrating.hidden = NO;
        SQCheck(@"fixture starts in another real scene", migrating.windowScene == compatibility && compatibility != scene);
        [self scene:scene willConnectToSession:self.testSession options:self.testOptions];
        SQCheck(@"compatibility Qt window migrates to app scene", self.window == migrating && migrating.windowScene == scene);
        SQCheck(@"visible Qt window is hidden before migration", migrating.migratedWhileHidden);
        SQCheck(@"Qt show intent survives scene migration", !migrating.hidden);
        QIOSDesktopManagerView *migratedDesktop = ((QIOSViewController *)migrating.rootViewController).desktop;
        [migratedDesktop layoutSubviews];
        SQCheck(@"migrated nested Qt content fills desktop", SQRectEqual(migratedDesktop.mainContent.frame, migratedDesktop.bounds));
        [self sceneDidDisconnect:scene];
        migrating.hidden = YES;
        migrating.rootViewController = nil;
        app.window = nil;
        [self scene:scene willConnectToSession:self.testSession options:self.testOptions];
        QUIWindow *hiding = [[QUIWindow alloc] initWithFrame:CGRectMake(0, 0, 320, 180)];
        QIOSViewController *hidingController = [QIOSViewController new];
        hidingController.hideWindowDuringLoad = hiding;
        hiding.rootViewController = hidingController;
        hidingController.view = nil;
        SQCheck(@"hide-during-load fixture starts lazy", !hidingController.isViewLoaded);
        hiding.hidden = NO;
        SQCheck(@"root-load hide request survives outer show", self.window == hiding && hiding.hidden);
        dispatch_async(dispatch_get_main_queue(), ^{
            SQCheck(@"attachment retry preserves root-load hide intent", hiding.hidden);
            hidingController.hideWindowDuringLoad = nil;
            hiding.hidden = NO;
            SQCheck(@"later explicit Qt show restores visibility", !hiding.hidden && hiding.windowScene == scene);
            SQWriteResult(nil);
        });
    });
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(SQAdapterRuntimeAppDelegate.class));
    }
}
