// Source-built scene adapter for SQ MixPad 1.60.1 (1.60.1.92418).
// Qt continues to own its controllers and content. This bridge only attaches
// the existing main window and fits its desktop's main QUIView to scene bounds.
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <math.h>
#import <stdio.h>
#import <stdlib.h>

@interface MixPadSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

typedef UIWindow *(*MPInitIMP)(id __attribute__((ns_consumed)), SEL, CGRect)
    __attribute__((ns_returns_retained));
typedef void (*MPHiddenIMP)(UIWindow *, SEL, BOOL);
typedef void (*MPLayoutIMP)(UIView *, SEL);
static MPInitIMP MPOriginalInit;
static MPHiddenIMP MPOriginalHidden;
static MPLayoutIMP MPOriginalLayout;
static NSHashTable<UIWindow *> *MPWindows;
static NSMapTable<UIView *, UIView *> *MPDesktopContents;
static __weak UIWindowScene *MPScene;
static __weak MixPadSceneDelegate *MPDelegate;
static __weak UIWindow *MPMainWindow;
static __weak UIWindow *MPQueuedWindow;
static BOOL MPAttaching;
static BOOL MPChangingScene;
static NSHashTable<UIView *> *MPFittingDesktops;
static BOOL MPRetryScheduled;
static NSMapTable<UIWindow *, NSNumber *> *MPVisibilityRequests;

static void MPTraceWindow(const char *event, UIWindow *window) {
    if (!getenv("MIXPAD_SCENE_DEBUG")) return;
    fprintf(stderr, "MixPadScene %s window=%s root=%s loadedView=%s hidden=%d level=%.0f scene=%p target=%p\n",
        event, window ? class_getName(window.class) : "none",
        window.rootViewController ? class_getName(window.rootViewController.class) : "none",
        window.rootViewController.viewIfLoaded ? class_getName(window.rootViewController.viewIfLoaded.class) : "none",
        window.hidden, (double)window.windowLevel, (__bridge void *)window.windowScene, (__bridge void *)MPScene);
}

static BOOL MPWantsVisible(UIWindow *window) {
    if (!window) return NO;
    NSNumber *request = [MPVisibilityRequests objectForKey:window];
    return request ? request.boolValue : !window.hidden;
}

static void MPOnMain(dispatch_block_t work) {
    if ([NSThread isMainThread]) work();
    else dispatch_sync(dispatch_get_main_queue(), work);
}

static BOOL MPIsKind(id object, const char *name) {
    Class cls = objc_getClass(name);
    return cls && [object isKindOfClass:cls];
}

static BOOL MPUsableBounds(CGRect bounds) {
    return isfinite(bounds.origin.x) && isfinite(bounds.origin.y) &&
        isfinite(bounds.size.width) && isfinite(bounds.size.height) &&
        bounds.size.width > 0 && bounds.size.height > 0;
}

static BOOL MPEqualRects(CGRect lhs, CGRect rhs) {
    return lhs.origin.x == rhs.origin.x && lhs.origin.y == rhs.origin.y &&
        lhs.size.width == rhs.size.width && lhs.size.height == rhs.size.height;
}

static CGRect MPSceneBounds(UIWindowScene *scene) {
    if (@available(iOS 26.0, *)) {
        CGRect bounds = scene.effectiveGeometry.coordinateSpace.bounds;
        if (MPUsableBounds(bounds)) return bounds;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return scene.coordinateSpace.bounds;
#pragma clang diagnostic pop
}

static BOOL MPIsMainCandidate(UIWindow *window) {
    // Native dialogs and Qt tool/popup windows must retain their own geometry.
    // Qt may still own a compatibility scene, or defer loading its root view
    // until it has a scene. Neither condition may prevent migrating its window.
    return window && MPIsKind(window, "QUIWindow") &&
        window.windowLevel == UIWindowLevelNormal &&
        (window.rootViewController || MPWantsVisible(window));
}

static void MPTrack(UIWindow *window) {
    if (!window || !MPIsKind(window, "QUIWindow")) return;
    if (!MPWindows) MPWindows = [NSHashTable weakObjectsHashTable];
    [MPWindows addObject:window];
}

static UIWindow *MPSelectWindow(UIWindow *preferred) {
    if (MPIsMainCandidate(MPMainWindow)) return MPMainWindow;
    // The first Qt window that asked to be shown is the launch window, even
    // when UIKit kept it hidden because no application scene was connected.
    if (MPIsMainCandidate(MPQueuedWindow) && MPWantsVisible(MPQueuedWindow)) return MPQueuedWindow;
    if (MPIsMainCandidate(preferred) && MPWantsVisible(preferred)) return preferred;
    id<UIApplicationDelegate> appDelegate = UIApplication.sharedApplication.delegate;
    UIWindow *delegateWindow = [appDelegate respondsToSelector:@selector(window)] ?
        appDelegate.window : nil;
    // Otherwise use explicit application ownership, then visible tracked Qt UI.
    if (MPIsMainCandidate(delegateWindow)) return delegateWindow;
    UIWindow *best = nil;
    CGFloat bestArea = -1;
    for (UIWindow *window in MPWindows.allObjects) {
        if (!MPIsMainCandidate(window) || !MPWantsVisible(window)) continue;
        CGFloat area = window.bounds.size.width * window.bounds.size.height;
        if (!best || (best.hidden && !window.hidden) ||
            (best.hidden == window.hidden && area > bestArea)) {
            best = window;
            bestArea = area;
        }
    }
    return best;
}

static void MPUpdateGeometry(UIWindow *window, UIWindowScene *scene) {
    if (!window || !scene || window.windowScene != scene) return;
    CGRect bounds = MPSceneBounds(scene);
    if (MPUsableBounds(bounds) && !MPEqualRects(window.frame, bounds))
        window.frame = bounds;
    // setNeedsLayout schedules Qt's existing layout instead of recursively
    // forcing layout from within a Qt layout/visibility callback.
    [window.rootViewController.view setNeedsLayout];
}

static UIWindow *MPAttach(UIWindow *preferred) {
    UIWindowScene *scene = MPScene;
    if (!scene || MPAttaching) return MPMainWindow;
    UIWindow *window = MPSelectWindow(preferred);
    if (!window) return nil;
    MPAttaching = YES;
    @try {
        if (![MPVisibilityRequests objectForKey:window]) {
            if (!MPVisibilityRequests) MPVisibilityRequests = [NSMapTable weakToStrongObjectsMapTable];
            [MPVisibilityRequests setObject:@(!window.hidden) forKey:window];
        }
        MPTraceWindow("attaching", window);
        MPMainWindow = window;
        MPDelegate.window = window;
        if (window.windowScene != scene) {
            // UIKit requires a visible window to be hidden before migrating it
            // from Qt's compatibility scene to the application scene.
            MPChangingScene = YES;
            @try {
                if (window.windowScene) MPOriginalHidden(window, @selector(setHidden:), YES);
                window.windowScene = scene;
            } @finally {
                MPChangingScene = NO;
            }
        }
        [window.rootViewController loadViewIfNeeded];
        MPUpdateGeometry(window, scene);
        if (MPWantsVisible(window) && window.hidden) MPOriginalHidden(window, @selector(setHidden:), NO);
        MPTraceWindow("attached", window);
    } @finally {
        MPAttaching = NO;
    }
    return window;
}

static void MPMakeKeyIfNeeded(UIWindow *window) {
    if (!window || window.hidden || window.isKeyWindow) return;
    for (UIWindow *other in window.windowScene.windows) {
        if (other != window && !other.hidden && other.isKeyWindow) return;
    }
    [window makeKeyWindow];
}

static void MPScheduleAttachment(void) {
    // initWithFrame: can return before Qt installs the root controller. The
    // visibility and desktop hooks provide further retries if this turn is early.
    if (MPRetryScheduled) return;
    MPRetryScheduled = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        MPRetryScheduled = NO;
        UIWindow *window = MPAttach(nil);
        MPMakeKeyIfNeeded(window);
    });
}

static UIWindow *MPInitWindow(id __attribute__((ns_consumed)) object, SEL selector,
                             CGRect frame) __attribute__((ns_returns_retained));
static UIWindow *MPInitWindow(id __attribute__((ns_consumed)) object, SEL selector,
                             CGRect frame) {
    __block UIWindow *window;
    MPOnMain(^{
        window = MPOriginalInit(object, selector, frame);
        MPTrack(window);
        MPScheduleAttachment();
    });
    return window;
}

static void MPSetHidden(UIWindow *window, SEL selector, BOOL hidden) {
    MPOnMain(^{
        MPTrack(window);
        if (!MPChangingScene) {
            if (!MPVisibilityRequests) MPVisibilityRequests = [NSMapTable weakToStrongObjectsMapTable];
            [MPVisibilityRequests setObject:@(!hidden) forKey:window];
        }
        MPTraceWindow(hidden ? "hide request" : "show request", window);
        if (!hidden && !MPAttaching) {
            if (!MPQueuedWindow && (!MPScene || !MPMainWindow)) MPQueuedWindow = window;
            MPAttach(window); // Associate a scene before UIKit shows the window.
        }
        // Root loading may issue a newer hide request during MPAttach. Honor
        // that request instead of replaying the outer, older show request.
        BOOL effectiveHidden = MPChangingScene ? hidden : !MPWantsVisible(window);
        MPOriginalHidden(window, selector, effectiveHidden);
        if (!effectiveHidden && !MPAttaching) {
            UIWindow *attached = MPAttach(window); // Qt may install content here.
            if (attached == window) MPMakeKeyIfNeeded(window);
            MPScheduleAttachment();
        }
    });
}

static UIView *MPContent(UIView *desktop) {
    UIView *content = [MPDesktopContents objectForKey:desktop];
    if (content.superview == desktop && !content.hidden && content.alpha > 0 &&
        MPIsKind(content, "QUIView")) return content;
    content = nil;
    CGFloat largestArea = 0;
    for (UIView *child in desktop.subviews) {
        if (child.hidden || child.alpha <= 0 || !MPIsKind(child, "QUIView")) continue;
        CGFloat area = child.bounds.size.width * child.bounds.size.height;
        if (isfinite(area) && area > largestArea) {
            content = child;
            largestArea = area;
        }
    }
    if (!MPDesktopContents) MPDesktopContents = [NSMapTable weakToWeakObjectsMapTable];
    if (content) [MPDesktopContents setObject:content forKey:desktop];
    else [MPDesktopContents removeObjectForKey:desktop];
    return content;
}

static void MPLayoutDesktop(UIView *desktop, SEL selector) {
    MPOnMain(^{
        if ([MPFittingDesktops containsObject:desktop]) return;
        if (!MPFittingDesktops) MPFittingDesktops = [NSHashTable weakObjectsHashTable];
        [MPFittingDesktops addObject:desktop];
        @try {
            MPOriginalLayout(desktop, selector);
            UIWindow *window = desktop.window;
            if (!MPScene || !MPIsMainCandidate(window)) return;
            MPTrack(window);
            if (!MPMainWindow) MPAttach(window);
            // Qt's desktop can be nested below the controller's root view.
            if (window != MPMainWindow) return;
            UIView *content = MPContent(desktop);
            CGRect bounds = desktop.bounds;
            if (content && MPUsableBounds(bounds) &&
                !MPEqualRects(content.frame, bounds)) content.frame = bounds;
        } @finally {
            [MPFittingDesktops removeObject:desktop];
        }
    });
}

static IMP MPReplace(Class cls, SEL selector, IMP replacement) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return NULL;
    IMP original = method_getImplementation(method);
    // setHidden: is inherited in this Qt build. Adding a method to QUIWindow
    // avoids replacing UIWindow's implementation for every native dialog.
    if (!class_addMethod(cls, selector, replacement, method_getTypeEncoding(method)))
        method_setImplementation(class_getInstanceMethod(cls, selector), replacement);
    return original;
}

@implementation MixPadSceneDelegate
+ (void)load {
    Class windowClass = objc_getClass("QUIWindow");
    Class desktopClass = objc_getClass("QIOSDesktopManagerView");
    if (windowClass) {
        MPOriginalInit = (MPInitIMP)MPReplace(windowClass, @selector(initWithFrame:),
                                             (IMP)MPInitWindow);
        MPOriginalHidden = (MPHiddenIMP)MPReplace(windowClass, @selector(setHidden:),
                                                 (IMP)MPSetHidden);
    }
    if (desktopClass)
        MPOriginalLayout = (MPLayoutIMP)MPReplace(desktopClass, @selector(layoutSubviews),
                                                 (IMP)MPLayoutDesktop);
}

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)connectionOptions {
    if (![scene isKindOfClass:UIWindowScene.class]) return;
    MPOnMain(^{
        MPScene = (UIWindowScene *)scene;
        MPDelegate = self;
        MPTraceWindow("scene connected; queued", MPQueuedWindow);
        UIWindow *window = MPAttach(nil);
        MPMakeKeyIfNeeded(window);
        MPScheduleAttachment();
    });
}

- (void)sceneDidBecomeActive:(UIScene *)scene {
    MPOnMain(^{
        if (scene != MPScene) return;
        UIWindow *window = MPAttach(nil);
        MPMakeKeyIfNeeded(window);
        MPScheduleAttachment();
    });
}

- (void)windowScene:(UIWindowScene *)windowScene
    didUpdateEffectiveGeometry:(UIWindowSceneGeometry *)previousEffectiveGeometry
    API_AVAILABLE(ios(26.0)) {
    MPOnMain(^{
        if (windowScene == MPScene) MPUpdateGeometry(MPAttach(nil), windowScene);
    });
}

- (void)windowScene:(UIWindowScene *)windowScene
    didUpdateCoordinateSpace:(id<UICoordinateSpace>)previousCoordinateSpace
    interfaceOrientation:(UIInterfaceOrientation)previousInterfaceOrientation
    traitCollection:(UITraitCollection *)previousTraitCollection {
    MPOnMain(^{
        if (windowScene == MPScene) MPUpdateGeometry(MPAttach(nil), windowScene);
    });
}

- (void)sceneDidDisconnect:(UIScene *)scene {
    MPOnMain(^{
        if (scene != MPScene) return;
        UIWindow *window = MPMainWindow;
        MPQueuedWindow = window;
        // Clear global state first: Qt visibility/layout callbacks during
        // detachment must not attach the window back to the disconnected scene.
        MPScene = nil;
        MPMainWindow = nil;
        MPDelegate = nil;
        self.window = nil;
        if (window.windowScene == scene) window.windowScene = nil;
    });
}
@end
