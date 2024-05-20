//
//  AuditModel.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 17.05.2024.
//

import Cocoa
import SystemExtensions

class AuditModel: NSObject {
    let notificationCenter = NotificationCenter()
    static let runningDidChangeNotification = NSNotification.Name("runningDidChange")
    static let trackingDirectoriesDidChangeNotification = NSNotification.Name("trackingDirectoriesDidChange")
    static let logDestinationDidChangeNotification = NSNotification.Name("logDestinationDidChange")
    
    var canRun: Bool {
        !trackingDirectories.isEmpty && logDestination != nil
    }
    
    var running: Bool = false {
        didSet {
            guard oldValue != running else {
                return
            }
            if running {
                guard !trackingDirectories.isEmpty, let logDestination else {
                    running = false
                    return
                }
                ExtensionClientConnection.shared.startAudit(directories: trackingDirectories, logDestination: logDestination)
            } else {
                ExtensionClientConnection.shared.stopAudit()
            }
            notificationCenter.post(name: AuditModel.runningDidChangeNotification, object: self)
        }
    }
    
    @UserDefaultsStorage(key: "stopsAuditOnAppTermination", defaultValue: false)
    var stopsAuditOnAppTermination
    
    func activateExtension() {
        guard let extensionIdentifier = extensionIdentifier(from: extensionBundle) else {
            return
        }
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionIdentifier,
                             queue: DispatchQueue.main)
        request.delegate = self
        let extensionManager = OSSystemExtensionManager.shared
        extensionManager.submitRequest(request)
    }
    
    private func connectToExtension() {
        ExtensionClientConnection.shared.register(withExtension: extensionBundle, delegate: self) { success in
            if success {
                ExtensionClientConnection.shared.getConfig { running, trackingDirectories, logDestination in
                    DispatchQueue.main.async { [weak self] in
                        guard let self else {
                            return
                        }
                        self.trackingDirectories = trackingDirectories
                        self.logDestination = logDestination
                        self.running = running
                    }
                }
            }
        }
    }
    
    private (set) var trackingDirectories = Array<URL>() {
        didSet {
            guard oldValue != trackingDirectories else {
                return
            }
            notificationCenter.post(name: AuditModel.trackingDirectoriesDidChangeNotification, object: self)
        }
    }
    
    func addTracking(directories: [URL]) {
        let uniqueDirectories = Set(directories).subtracting(trackingDirectories)
        trackingDirectories.append(contentsOf: uniqueDirectories)
    }
    
    func removeTracking(indexes: IndexSet) {
        guard indexes.allSatisfy(trackingDirectories.indices.contains) else {
            return
        }
        trackingDirectories.remove(atOffsets: indexes)
    }
    
    var logDestination: URL? {
        didSet {
            notificationCenter.post(name: AuditModel.logDestinationDidChangeNotification, object: self)
        }
    }
    
    private lazy var extensionBundle: Bundle = {

        let extensionsDirectoryURL = URL(fileURLWithPath: "Contents/Library/SystemExtensions", relativeTo: Bundle.main.bundleURL)
        let extensionURLs: [URL]
        do {
            extensionURLs = try FileManager.default.contentsOfDirectory(at: extensionsDirectoryURL,
                                                                        includingPropertiesForKeys: nil,
                                                                        options: .skipsHiddenFiles)
        } catch let error {
            fatalError("Failed to get the contents of \(extensionsDirectoryURL.absoluteString): \(error.localizedDescription)")
        }

        guard let extensionURL = extensionURLs.first else {
            fatalError("Failed to find any system extensions")
        }

        guard let extensionBundle = Bundle(url: extensionURL) else {
            fatalError("Failed to create a bundle with URL \(extensionURL.absoluteString)")
        }

        return extensionBundle
    }()
}

extension AuditModel: OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
    
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    }
    
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed {
            connectToExtension()
        }
    }
    
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error) {
        connectToExtension()
    }
}

extension AuditModel: ClientCommunication {
    func auditStopped() {
        DispatchQueue.main.async { [weak self] in
            self?.running = false
        }
    }
}
