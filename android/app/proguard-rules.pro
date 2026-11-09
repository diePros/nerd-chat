# JNI: the library exports Java_app_sineloco_model_NativeBridge_nInit / _nCall. Renaming or removing this class or its methods breaks the lookup.
-keep class app.sineloco.model.NativeBridge { *; }
-keep class app.sineloco.model.Native { *; }
# the core calls the key store by name (wrap/unwrap/erase) through JNI
-keep interface app.sineloco.model.PlatformKeys { *; }
-keep class * implements app.sineloco.model.PlatformKeys { *; }
