//go:build android || ios

package mobile

// gomobile bind generates code that imports golang.org/x/mobile/bind; this blank
// import ensures that package (and its go.sum entries) is part of the module
// graph so `gobind` can resolve it — otherwise it fails with "no Go package in
// golang.org/x/mobile/bind". The android/ios build constraint means it is linked
// exactly when gomobile cross-compiles, and never in the desktop agent build.
import _ "golang.org/x/mobile/bind"
