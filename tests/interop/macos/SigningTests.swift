import AppKit
import XCTest

@MainActor
final class SigningTests: XCTestCase {
    private let app = XCUIApplication(bundleIdentifier: "org.firmica.client")
    private var origin: String { ProcessInfo.processInfo.environment["FIRMICA_TEST_ORIGIN"]! }

    private func json(_ route: String) throws -> [String: Any] {
        let data = try Data(contentsOf: URL(string: origin + route)!)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func wait(_ condition: () throws -> Bool, seconds: TimeInterval = 20,
                      file: StaticString = #filePath, line: UInt = #line) throws {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if try condition() { return }
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        XCTFail("Condition timed out\n\(app.debugDescription)", file: file, line: line)
        throw NSError(domain: "FirmicaNativeQA", code: 1)
    }

    private func element(_ identifier: String, type: XCUIElement.ElementType = .any) -> XCUIElement {
        app.descendants(matching: type).matching(identifier: identifier).firstMatch
    }

    private func english() throws {
        // Home has a separate language toggle; wait for the signing screen itself.
        try wait({
            self.app.buttons["Certificado PKCS#12 (hasta 8 MiB)"].exists ||
                self.app.buttons["PKCS#12 certificate (up to 8 MiB)"].exists
        }, seconds: 15)
        let button = app.buttons["English"]
        if button.exists { button.click() }
        XCTAssertTrue(app.buttons["Español"].waitForExistence(timeout: 10))
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

    private func command(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        return String(decoding: data, as: UTF8.self)
    }

    private func workers() throws -> [Int] {
        guard let process = NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first else { return [] }
        return try json("/workers/\(process.processIdentifier)")["workers"] as! [Int]
    }

    private func choose(_ identifier: String, path: String?, certificate: Bool = false) throws {
        let target = element(identifier, type: .button)
        if target.exists { target.click() }
        else {
            // WebKit names these buttons from their enclosing document/certificate label.
            let button = app.buttons[certificate ? "PKCS#12 certificate (up to 8 MiB)" : "Document (up to 16 MiB)"]
            XCTAssertTrue(button.waitForExistence(timeout: 10), app.debugDescription)
            button.click()
        }
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 10))
        if let path {
            app.typeKey("g", modifierFlags: [.command, .shift])
            app.typeText(path)
            app.typeKey(.return, modifierFlags: [])
            let open = app.sheets.buttons["Open"].firstMatch
            try wait { open.exists && open.isEnabled }
            open.click()
        } else {
            app.typeKey(.escape, modifierFlags: [])
        }
        try wait { !app.sheets.firstMatch.exists }
    }

    private func select(_ identifier: String, label: String, index: Int) {
        let popup = element(identifier, type: .popUpButton)
        if popup.exists { popup.click() } else { app.popUpButtons.element(boundBy: index).click() }
        app.menuItems[label].firstMatch.click()
    }

    private func consent() -> XCUIElement {
        let checkbox = element("sign-acknowledge", type: .checkBox)
        return checkbox.exists ? checkbox : app.checkBoxes["I authorize signing this document with this certificate and accept the unchecked items shown above."]
    }

    private func prepare(_ scenario: [String: Any], password: String, local: Bool) throws {
        try choose("sign-certificate", path: scenario["certificate"] as? String, certificate: true)
        let field = app.secureTextFields.firstMatch
        field.click()
        field.typeText(password)
        if local {
            if scenario["algorithm"] as? String == "ec" { select("sign-algorithm", label: "ECDSA P-256 / SHA-256", index: 0) }
            let mode = scenario["mode"] as! String
            if scenario["attached"] as? Bool == true { app.checkBoxes["Embed the document in the signature"].click() }
            if mode != "cades" {
                let labels = ["pades": "PAdES", "enveloped": "XAdES (enveloped)", "enveloping": "XAdES (enveloping)", "detached": "XAdES (internally detached)"]
                select("sign-format", label: labels[mode]!, index: 1)
                if mode == "pades" { app.checkBoxes["Visible signature"].click() }
            }
        }
        let review = app.buttons["Open and review"]
        try wait { review.isEnabled }
        review.click()
        let acknowledgment = consent()
        XCTAssertTrue(acknowledgment.waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
        XCTAssertEqual(try workers().count, 1)
        let sign = app.buttons[local ? "Sign and save…" : "Sign and send to browser"]
        XCTAssertFalse(sign.isEnabled)
        XCTAssertFalse(app.secureTextFields.firstMatch.exists)
    }

    private func save(_ path: String, cancel: Bool) throws {
        app.buttons["Sign and save…"].click()
        XCTAssertTrue(app.sheets.firstMatch.waitForExistence(timeout: 10))
        if cancel {
            app.typeKey(.escape, modifierFlags: [])
        } else {
            let url = URL(fileURLWithPath: path)
            app.typeKey("g", modifierFlags: [.command, .shift])
            app.typeText(url.deletingLastPathComponent().path)
            app.typeKey(.return, modifierFlags: [])
            let name = app.sheets.textFields["Save As:"]
            let field = name.exists ? name : app.sheets.textFields.firstMatch
            field.click()
            field.typeKey("a", modifierFlags: .command)
            field.typeText(url.lastPathComponent)
            app.sheets.buttons["Save"].firstMatch.click()
        }
        try wait { !app.sheets.firstMatch.exists }
    }

    func testLocalAndBrowserSigning() throws {
        continueAfterFailure = false
        let config = try json("/config")
        let local = config["local"] as! [[String: Any]]
        let browser = config["browser"] as! [[String: Any]]
        let password = config["password"] as! String
        for (index, scenario) in local.enumerated() {
            // Exercise the distributed application's normal LaunchServices entry point.
            let evidence = config["evidence"] as! String
            _ = try command("/usr/bin/open", ["-a", config["app"] as! String,
                "--stdout", evidence + "/application.stdout.log", "--stderr", evidence + "/application.stderr.log"])
            try wait { NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first?.bundleURL != nil }
            XCTAssertEqual(NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first?.bundleURL?.resolvingSymlinksInPath().path,
                URL(fileURLWithPath: config["app"] as! String).resolvingSymlinksInPath().path)
            app.activate()
            XCTAssertTrue(app.links["Sign a document"].waitForExistence(timeout: 15))
            app.links["Sign a document"].click()
            try english()
            if index == 0 {
                try choose("sign-document", path: nil)
                XCTAssertFalse(app.buttons["Open and review"].isEnabled)
                try choose("sign-certificate", path: nil, certificate: true)
                XCTAssertFalse(app.buttons["Open and review"].isEnabled)
            }
            try choose("sign-document", path: scenario["document"] as? String)
            try prepare(scenario, password: password, local: true)
            // Approval must retain the reviewed bytes after the selected file changes.
            _ = try json("/mutate/\(index)")
            XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
            consent().click()
            let destination = scenario["output"] as! String
            if index == 0 {
                try save(destination, cancel: true)
                XCTAssertEqual(try json("/output/\(index)")["exists"] as? Bool, false)
                XCTAssertEqual(try workers().count, 1)
            }
            try save(destination, cancel: false)
            XCTAssertTrue(app.staticTexts["Signature saved."].waitForExistence(timeout: 20))
            XCTAssertEqual(try workers().count, 0)
            XCTAssertEqual(try json("/output/\(index)")["exists"] as? Bool, true)
            capture("local-\(index)")
            app.terminate()
        }
        _ = try json("/local-done")
        try wait({ try self.json("/state")["browser_ready"] as? Bool == true }, seconds: 180)
        for (index, scenario) in browser.enumerated() {
            try wait({
                let state = try self.json("/state")
                return state["index"] as? Int == index && state["started"] as? Bool == true
            }, seconds: 45)
            try wait { NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first?.bundleURL != nil }
            XCTAssertEqual(NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first?.bundleURL?.resolvingSymlinksInPath().path,
                URL(fileURLWithPath: config["app"] as! String).resolvingSymlinksInPath().path)
            app.activate()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
            try english()
            XCTAssertFalse(app.buttons["Document (up to 16 MiB)"].exists)
            try prepare(scenario, password: password, local: false)
            // LaunchServices must deliver to this instance without replacing pending consent.
            let before = NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first!.processIdentifier
            _ = try command("/usr/bin/open", ["-b", "org.firmica.client", "afirma://cosign?ver=4&format=CAdES"])
            XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
            XCTAssertFalse(app.buttons["Sign and send to browser"].isEnabled)
            XCTAssertEqual(NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first!.processIdentifier, before)
            _ = try command("/usr/bin/open", ["-b", "org.firmica.client", "afirma://sign?ver=4&dat=%00"])
            XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
            let action = scenario["action"] as! String
            _ = try json("/prepared")
            if index == 0 {
                app.typeKey("h", modifierFlags: .command)
                try wait {
                    NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first?.isHidden == true
                }
                _ = try json("/hidden")
                try wait { try self.json("/state")["warm_delivered"] as? Bool == true }
                XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
                XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
                XCTAssertFalse(app.buttons["Sign and send to browser"].isEnabled)
            }
            if action == "cancel" {
                app.buttons["Cancel"].click()
            } else if action == "worker-failure" {
                let process = try XCTUnwrap(NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first)
                _ = try json("/kill-worker/\(process.processIdentifier)")
                consent().click()
                app.buttons["Sign and send to browser"].click()
            } else if action == "disconnect" {
                try wait({ !self.consent().exists }, seconds: 130)
            } else {
                consent().click()
                app.buttons["Sign and send to browser"].click()
            }
            try wait({ try self.json("/state")["result_received"] as? Bool == true }, seconds: 30)
            try wait { try self.workers().isEmpty }
            capture("browser-\(index)-\(action)")
            app.terminate()
            _ = try json("/native-done")
        }
    }
}
