# JNI: the library exports Java_app_nerdchat_model_NativeBridge_nInit / _nCall. Renaming or removing this class or its methods breaks the lookup.
-keep class app.nerdchat.model.NativeBridge { *; }
-keep class app.nerdchat.model.Native { *; }
# the core calls the key store by name (wrap/unwrap/erase) through JNI
-keep interface app.nerdchat.model.PlatformKeys { *; }
-keep class * implements app.nerdchat.model.PlatformKeys { *; }
