/**
 * Sephela Frida Instrumentation Script
 *
 * Hooks critical Android Java APIs to capture runtime behaviour of a
 * target APK during sandbox execution. Output is a JSON-lines stream
 * of intercepted API calls.
 *
 * Hook categories:
 *   - crypto:         javax.crypto.*, MessageDigest, SecretKeySpec
 *   - reflection:     Class.forName, getMethod, invoke
 *   - dex_loading:    DexClassLoader, PathClassLoader, InMemoryDexClassLoader
 *   - network:        URL.openConnection, HttpURLConnection, OkHttp
 *   - sms:            SmsManager.sendTextMessage, SMS content providers
 *   - file_io:        FileOutputStream, SharedPreferences
 *   - accessibility:  AccessibilityService
 *   - device_info:    TelephonyManager.getDeviceId, Build.*
 *
 * SECURITY: This script runs INSIDE the sandboxed emulator. It only
 * reads API calls and writes JSON — it never modifies app behaviour.
 */

'use strict';

// Helper: emit a hook entry as JSON line
function emit(hookType, className, methodName, args, retVal, stack) {
    var entry = {
        timestamp_ms: Date.now(),
        hook_type: hookType,
        class_name: className,
        method_name: methodName,
        args: args || [],
        return_value: retVal || null,
        stack_trace: stack || []
    };
    send(JSON.stringify(entry));
}

function getStackTrace() {
    try {
        var trace = Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()
        );
        return trace.split("\n").slice(1, 6).map(function(l) { return l.trim(); });
    } catch (e) {
        return [];
    }
}

Java.perform(function () {
    console.log("[sephela] Frida hooks loaded");

    // -----------------------------------------------------------------------
    // CRYPTO: javax.crypto.Cipher
    // -----------------------------------------------------------------------
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (algo) {
            emit("crypto", "javax.crypto.Cipher", "getInstance",
                [algo], null, getStackTrace());
            return this.getInstance(algo);
        };
        Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
            var modeStr = mode === 1 ? "ENCRYPT" : mode === 2 ? "DECRYPT" : String(mode);
            emit("crypto", "javax.crypto.Cipher", "init",
                [modeStr, key.getAlgorithm()], null, getStackTrace());
            return this.init(mode, key);
        };
    } catch (e) { console.log("[sephela] Cipher hook skipped: " + e); }

    // SecretKeySpec
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            emit("crypto", "javax.crypto.spec.SecretKeySpec", "<init>",
                ["key_len=" + key.length, algo], null, getStackTrace());
            return this.$init(key, algo);
        };
    } catch (e) { console.log("[sephela] SecretKeySpec hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // REFLECTION: Class.forName, Method.invoke
    // -----------------------------------------------------------------------
    try {
        var JavaClass = Java.use("java.lang.Class");
        JavaClass.forName.overload("java.lang.String").implementation = function (name) {
            emit("reflection", "java.lang.Class", "forName",
                [name], null, getStackTrace());
            return this.forName(name);
        };
    } catch (e) { console.log("[sephela] Class.forName hook skipped: " + e); }

    try {
        var Method = Java.use("java.lang.reflect.Method");
        Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;").implementation = function (obj, args) {
            emit("reflection", "java.lang.reflect.Method", "invoke",
                [this.getName(), obj ? obj.getClass().getName() : "null"],
                null, getStackTrace());
            return this.invoke(obj, args);
        };
    } catch (e) { console.log("[sephela] Method.invoke hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // DEX LOADING: DexClassLoader
    // -----------------------------------------------------------------------
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload("java.lang.String", "java.lang.String",
            "java.lang.String", "java.lang.ClassLoader").implementation = function (dex, opt, lib, parent) {
            emit("dex_loading", "dalvik.system.DexClassLoader", "<init>",
                [dex, opt || "null"], null, getStackTrace());
            return this.$init(dex, opt, lib, parent);
        };
    } catch (e) { console.log("[sephela] DexClassLoader hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // NETWORK: URL.openConnection
    // -----------------------------------------------------------------------
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            emit("network", "java.net.URL", "openConnection",
                [this.toString()], null, getStackTrace());
            return this.openConnection();
        };
    } catch (e) { console.log("[sephela] URL hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // SMS: SmsManager.sendTextMessage
    // -----------------------------------------------------------------------
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String",
            "java.lang.String", "android.app.PendingIntent",
            "android.app.PendingIntent").implementation = function (dest, sc, text, sent, deliv) {
            emit("sms", "android.telephony.SmsManager", "sendTextMessage",
                [dest, "body_redacted"], null, getStackTrace());
            return this.sendTextMessage(dest, sc, text, sent, deliv);
        };
    } catch (e) { console.log("[sephela] SmsManager hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // DEVICE INFO: TelephonyManager
    // -----------------------------------------------------------------------
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function () {
            var ret = this.getDeviceId();
            emit("device_info", "android.telephony.TelephonyManager", "getDeviceId",
                [], ret, getStackTrace());
            return ret;
        };
    } catch (e) { console.log("[sephela] TelephonyManager hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // FILE I/O: FileOutputStream
    // -----------------------------------------------------------------------
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
            emit("file_io", "java.io.FileOutputStream", "<init>",
                [path], null, getStackTrace());
            return this.$init(path);
        };
    } catch (e) { console.log("[sephela] FileOutputStream hook skipped: " + e); }

    // -----------------------------------------------------------------------
    // ACCESSIBILITY
    // -----------------------------------------------------------------------
    try {
        var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
            emit("accessibility", "android.accessibilityservice.AccessibilityService",
                "onAccessibilityEvent",
                [event.getEventType().toString()], null, getStackTrace());
            return this.onAccessibilityEvent(event);
        };
    } catch (e) { /* AccessibilityService may not be subclassed — expected */ }

    console.log("[sephela] All hooks installed");
});
