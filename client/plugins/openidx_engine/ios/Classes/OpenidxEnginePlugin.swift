import Flutter
import UIKit

// `Engine` is the Swift module produced by
//   gomobile bind -target=ios -o Engine.xcframework ./agent/mobile
// gomobile names the module after the -o output (Engine), while the Go package
// (`mobile`) determines the function PREFIX — so the module is `Engine` but the
// funcs are `Mobile<Func>`. The funcs use the gomobile calling convention:
// value-returning funcs take an `NSErrorPointer` out-param and return the
// String; error-only funcs return (throw) an error. See README.md.
import Engine

public class OpenidxEnginePlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "openidx_engine",
      binaryMessenger: registrar.messenger())
    let instance = OpenidxEnginePlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any]

    // Run the Go bridge off the platform thread: ZitiDial and login can block
    // on network I/O, and we must never stall the UI/main thread.
    DispatchQueue.global(qos: .userInitiated).async {
      do {
        let value = try self.dispatch(call.method, args)
        DispatchQueue.main.async { result(value) }
      } catch let err as NSError {
        DispatchQueue.main.async {
          result(FlutterError(
            code: "engine_error",
            message: err.localizedDescription,
            details: "\(err.domain)#\(err.code)"))
        }
      }
    }
  }

  /// Maps a channel method name to the corresponding gomobile function. Returns
  /// the JSON string (or `nil` for void methods). Throws the Go error, which
  /// `handle` converts into a `FlutterError`.
  private func dispatch(_ method: String, _ args: [String: Any]?) throws -> Any? {
    switch method {
    case "start":
      try callVoid { MobileStart(str(args, "configDir"), $0) }
      return nil
    case "setServer":
      try callVoid { MobileSetServer(str(args, "url"), $0) }
      return nil
    case "status":
      return try callString { MobileStatus($0) }
    case "login":
      return try callString { MobileLogin($0) }
    case "loginStart":
      return try callString { MobileLoginStart($0) }
    case "loginFinish":
      return try callString { MobileLoginFinish(str(args, "callbackUrl"), $0) }
    case "logout":
      try callVoid { MobileLogout($0) }
      return nil
    case "enroll":
      let code = str(args, "code")
      return try callString { MobileEnroll(code, $0) }
    case "posture":
      return try callString { MobilePosture($0) }
    case "pamList":
      return try callString { MobilePamList($0) }
    case "pamConnect":
      let entryID = str(args, "entryId")
      return try callString { MobilePamConnect(entryID, $0) }
    case "pamRequest":
      try callVoid { MobilePamRequest(str(args, "entryId"), str(args, "reason"), $0) }
      return nil
    case "zitiDial":
      let service = str(args, "service")
      return try callString { MobileZitiDial(service, $0) }
    case "zitiClose":
      try callVoid { MobileZitiClose(str(args, "service"), $0) }
      return nil
    case "logs":
      return try callString { MobileLogs($0) }
    default:
      throw NSError(
        domain: "openidx_engine",
        code: -1,
        userInfo: [NSLocalizedDescriptionKey: "unimplemented method \(method)"])
    }
  }

  /// Invokes a gomobile `(String, error)` func using the `NSErrorPointer`
  /// convention and rethrows the error as a Swift throw.
  private func callString(_ body: (NSErrorPointer) -> String) throws -> String {
    var error: NSError?
    let value = body(&error)
    if let error = error { throw error }
    return value
  }

  /// Invokes a gomobile error-only func. gomobile generates these as
  /// `BOOL MobileX(..., NSError**)` (success flag + out-param), NOT as Swift
  /// `throws`, so we pass the NSErrorPointer explicitly, discard the BOOL, and
  /// rethrow any error.
  private func callVoid(_ body: (NSErrorPointer) -> Bool) throws {
    var error: NSError?
    _ = body(&error)
    if let error = error { throw error }
  }

  private func str(_ args: [String: Any]?, _ key: String) -> String {
    return (args?[key] as? String) ?? ""
  }
}
