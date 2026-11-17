#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <stdatomic.h>

static atomic_bool PatchRescanQueued;

static NSInteger PatchBehavior(id self, SEL selector) {
    if (@available(iOS 27.1, *)) {
        return PATCH_TOP ? UIVerticalBarBehaviorDisabled : UIVerticalBarBehaviorAutomatic;
    }
    return 0;
}

static BOOL PatchIsController(Class cls) {
    for (Class current = cls; current; current = class_getSuperclass(current)) {
        if (current == [UIViewController class]) return YES;
    }
    return NO;
}

static void PatchControllers(void) {
    if (@available(iOS 27.1, *)) {
        unsigned int count = 0;
        Class *classes = objc_copyClassList(&count);
        SEL selector = @selector(preferredVerticalBarBehavior);
        Method base = class_getInstanceMethod([UIViewController class], selector);
        const char *types = method_getTypeEncoding(base);
        for (unsigned int index = 0; index < count; index++) {
            Class cls = classes[index];
            if (!PatchIsController(cls)) continue;
            // Add on inheriting classes; replace only the class's own implementation.
            if (!class_addMethod(cls, selector, (IMP)PatchBehavior, types)) {
                class_replaceMethod(cls, selector, (IMP)PatchBehavior, types);
            }
        }
        free(classes);
    }
}

static void PatchImageAdded(const struct mach_header *header, intptr_t slide) {
    // dyld calls under its loader lock. Defer all Objective-C work to the main queue.
    if (atomic_exchange(&PatchRescanQueued, true)) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        atomic_store(&PatchRescanQueued, false);
        PatchControllers();
    });
}

@interface IPAPatcherBarsBootstrap : NSObject
@end
@implementation IPAPatcherBarsBootstrap
+ (void)load {
    if (@available(iOS 27.1, *)) {
        PatchControllers();
        _dyld_register_func_for_add_image(PatchImageAdded);
    }
}
@end
