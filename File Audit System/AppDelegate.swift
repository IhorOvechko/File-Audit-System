//
//  AppDelegate.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 14.05.2024.
//

import Cocoa

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    @IBOutlet var window: NSWindow!
    private var mainViewController: AuditSettingsViewController!
    private var mainModel: AuditModel!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        mainModel = AuditModel()
        mainViewController = AuditSettingsViewController(model: mainModel)
        guard let contentView = self.window.contentView else {
            return
        }
        mainViewController.view.frame = contentView.frame
        self.window.contentView?.addSubview(mainViewController.view)
        mainModel.activateExtension()
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        if mainModel.running && mainModel.stopsAuditOnAppTermination {
            mainModel.running = false
        }
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }
    
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

