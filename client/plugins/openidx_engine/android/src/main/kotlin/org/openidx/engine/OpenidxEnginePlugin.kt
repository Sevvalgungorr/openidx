package org.openidx.engine

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.Executors

// `mobile.Mobile` is the Kotlin/Java class produced by
//   gomobile bind -target=android -o engine.aar ./agent/mobile
// Its static methods mirror the package funcs: value-returning funcs return the
// String and throw `java.lang.Exception` on a Go error; error-only funcs return
// void and throw on error. The engine.aar is added as an implementation
// dependency (see build.gradle + README.md).
import mobile.Mobile

class OpenidxEnginePlugin : FlutterPlugin, MethodCallHandler {
  private lateinit var channel: MethodChannel

  // Go calls (login, ZitiDial) can block on I/O; keep them off the main thread.
  private val executor = Executors.newSingleThreadExecutor()
  private val main = Handler(Looper.getMainLooper())

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(binding.binaryMessenger, "openidx_engine")
    channel.setMethodCallHandler(this)
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
    executor.shutdown()
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    executor.execute {
      try {
        val value = dispatch(call)
        main.post { result.success(value) }
      } catch (e: Exception) {
        main.post {
          result.error("engine_error", e.message ?: e.toString(), e.javaClass.name)
        }
      }
    }
  }

  /** Maps a channel method to the gomobile static call. Returns the JSON String
   *  (or null for void methods); throws are surfaced as `result.error`. */
  private fun dispatch(call: MethodCall): Any? {
    return when (call.method) {
      "start" -> { Mobile.start(arg(call, "configDir")); null }
      "setServer" -> { Mobile.setServer(arg(call, "url")); null }
      "status" -> Mobile.status()
      "login" -> Mobile.login()
      "loginStart" -> Mobile.loginStart()
      "loginFinish" -> Mobile.loginFinish(arg(call, "callbackUrl"))
      "accessToken" -> Mobile.accessToken()
      "logout" -> { Mobile.logout(); null }
      "enroll" -> Mobile.enroll(arg(call, "code"))
      "posture" -> Mobile.posture()
      "pamList" -> Mobile.pamList()
      "pamConnect" -> Mobile.pamConnect(arg(call, "entryId"))
      "pamRequest" -> { Mobile.pamRequest(arg(call, "entryId"), arg(call, "reason")); null }
      "zitiDial" -> Mobile.zitiDial(arg(call, "service"))
      "zitiClose" -> { Mobile.zitiClose(arg(call, "service")); null }
      "logs" -> Mobile.logs()
      else -> throw IllegalArgumentException("unimplemented method ${call.method}")
    }
  }

  private fun arg(call: MethodCall, key: String): String = call.argument<String>(key) ?: ""
}
