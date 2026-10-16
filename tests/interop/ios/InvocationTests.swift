import XCTest

@MainActor
final class InvocationTests: XCTestCase {
    private let app = XCUIApplication(bundleIdentifier: "org.firmica.client")
    private let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")

    private func expect(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(app.staticTexts[text].firstMatch.waitForExistence(timeout: 20),
                      "Missing text: \(text)\n\(app.debugDescription)", file: file, line: line)
    }

    private func follow(_ label: String) {
        safari.activate()
        let link = safari.links[label]
        XCTAssertTrue(link.waitForExistence(timeout: 20), safari.debugDescription)
        link.tap()
        // Safari's SFDialogView exposes buttons outside the alerts container.
        let safariOpen = safari.buttons["Open"]
        if safariOpen.waitForExistence(timeout: 3) {
            safariOpen.tap()
        } else {
            let systemOpen = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.buttons["Open"]
            if systemOpen.exists { systemOpen.tap() }
        }
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 20), safari.debugDescription)
    }

    private func capture(_ name: String) {
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
        let hierarchy = XCTAttachment(string: app.debugDescription)
        hierarchy.name = name + " accessibility"
        hierarchy.lifetime = .keepAlways
        add(hierarchy)
    }

    func testBrowserColdWarmReview() throws {
        continueAfterFailure = false
        let origin = try XCTUnwrap(ProcessInfo.processInfo.environment["FIRMICA_TEST_ORIGIN"])
        if app.state != .notRunning { app.terminate() }
        safari.open(try XCTUnwrap(URL(string: origin)))
        let continueButton = safari.buttons["Continue"].firstMatch
        if continueButton.waitForExistence(timeout: 3) { continueButton.tap() }

        follow("Sign request")
        expect("sign")
        expect("4")
        capture("cold review")
        app.buttons["English"].tap()
        XCTAssertTrue(app.buttons["Reject"].waitForExistence(timeout: 10))

        // A warm launch cannot replace pending review. Language also detects a restart.
        follow("Save request")
        expect("sign")
        XCTAssertTrue(app.buttons["Reject"].exists)
        XCUIDevice.shared.press(.home)
        app.activate()
        expect("sign")
        XCTAssertTrue(app.buttons["Reject"].exists)
        app.buttons["Reject"].tap()
        expect("Request rejected.")

        follow("Co-sign request")
        expect("cosign")
        expect("3")
        XCTAssertTrue(app.buttons["Reject"].exists)
        app.buttons["Acknowledge review"].tap()
        expect("Review acknowledged. This operation is not implemented yet.")

        follow("Malformed request")
        expect("Review acknowledged. This operation is not implemented yet.")
        XCTAssertFalse(app.buttons["Reject"].exists)
        capture("warm terminal review")

        app.terminate()
        follow("Certificate request")
        expect("selectcert")
        expect("4")
        XCTAssertTrue(app.buttons["English"].exists)
        capture("fresh process review")
    }
}
