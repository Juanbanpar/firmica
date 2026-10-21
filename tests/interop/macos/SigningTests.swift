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

    private func english() {
        let button = app.buttons["English"]
        if button.waitForExistence(timeout: 2) { button.click() }
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

    private func workers() throws -> [String] {
        guard let process = NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first else { return [] }
        return try command("/bin/ps", ["-axo", "pid=,ppid=,comm="]).split(separator: "\n").compactMap { line in
            let fields = line.split(whereSeparator: { $0.isWhitespace })
            guard fields.count >= 3, fields[1] == String(process.processIdentifier), line.hasSuffix("/firmica-key-worker") else { return nil }
            return String(fields[0])
        }
    }

    private func choose(_ identifier: String, path: String?, certificate: Bool = false) throws {
        let target = element(identifier, type: .button)
        if target.exists { target.click() }
        else { app.buttons["Choose file…"].firstMatch.click() }
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
        return checkbox.exists ? checkbox : app.checkBoxes.matching(NSPredicate(format: "label BEGINSWITH %@", "I authorize signing")).firstMatch
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
            app.launch()
            XCTAssertTrue(app.links["Sign a document"].waitForExistence(timeout: 15))
            app.links["Sign a document"].click()
            english()
            if index == 0 {
                try choose("sign-document", path: nil)
                XCTAssertFalse(app.buttons["Open and review"].isEnabled)
            }
            try choose("sign-document", path: scenario["document"] as? String)
            try prepare(scenario, password: password, local: true)
            // Approval must retain the reviewed bytes after the selected file changes.
            try Data("changed after review".utf8).write(to: URL(fileURLWithPath: scenario["document"] as! String))
            XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
            consent().click()
            let destination = scenario["output"] as! String
            if index == 0 {
                try save(destination, cancel: true)
                XCTAssertFalse(FileManager.default.fileExists(atPath: destination))
                XCTAssertEqual(try workers().count, 1)
            }
            try save(destination, cancel: false)
            XCTAssertTrue(app.staticTexts["Signature saved."].waitForExistence(timeout: 20))
            XCTAssertEqual(try workers().count, 0)
            XCTAssertTrue(FileManager.default.fileExists(atPath: destination))
            capture("local-\(index)")
            app.terminate()
        }
        _ = try json("/local-done")
        for (index, scenario) in browser.enumerated() {
            try wait({
                let state = try self.json("/state")
                return state["index"] as? Int == index && state["started"] as? Bool == true
            }, seconds: 45)
            try wait { self.app.state != .notRunning }
            app.activate()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
            english()
            XCTAssertFalse(element("sign-document", type: .button).exists)
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
                XCTAssertTrue(NSRunningApplication.runningApplications(withBundleIdentifier: "org.firmica.client").first!.hide())
                _ = try json("/hidden")
                try wait { try self.json("/state")["warm_delivered"] as? Bool == true }
                XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10))
                XCTAssertTrue(app.staticTexts[scenario["hash"] as! String].exists)
                XCTAssertFalse(app.buttons["Sign and send to browser"].isEnabled)
            }
            if action == "cancel" {
                app.buttons["Cancel"].click()
            } else if action == "worker-failure" {
                let worker = try XCTUnwrap(workers().first)
                _ = try command("/bin/kill", ["-KILL", worker])
                consent().click()
                app.buttons["Sign and send to browser"].click()
            } else if action == "disconnect" {
                try wait { !self.consent().exists }
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
