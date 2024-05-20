//
//  ExtensionClientConnection.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 17.05.2024.
//

import Cocoa

class ExtensionClientConnection: NSObject {
    weak var delegate: ClientCommunication?
    var currentConnection: NSXPCConnection?
    static let shared = ExtensionClientConnection()
    
    func register(withExtension bundle: Bundle, delegate: ClientCommunication, completionHandler: @escaping (Bool) -> Void) {
        self.delegate = delegate

        guard currentConnection == nil else {
            completionHandler(true)
            return
        }
        
        guard let machServiceName = extensionMachServiceName(from: bundle) else {
            return
        }
        let newConnection = NSXPCConnection(machServiceName: machServiceName, options: [])
        
        newConnection.exportedInterface = NSXPCInterface(with: ClientCommunication.self)
        newConnection.exportedObject = delegate
        newConnection.remoteObjectInterface = NSXPCInterface(with: HostCommunication.self)
        
        currentConnection = newConnection
        newConnection.resume()
        
        guard let providerProxy = newConnection.remoteObjectProxyWithErrorHandler({ registerError in
            self.currentConnection?.invalidate()
            self.currentConnection = nil
            completionHandler(false)
        }) as? HostCommunication else {
            return
        }
        
        providerProxy.register(completionHandler)
    }
    
    func startAudit(directories: [URL], logDestination aLogDestination: URL) {
        guard let currentConnection else {
            return
        }
        
        guard let providerProxy = currentConnection.remoteObjectProxyWithErrorHandler({ registerError in
            self.currentConnection?.invalidate()
            self.currentConnection = nil
        }) as? HostCommunication else {
            return
        }
        
        let directoryPaths = directories.map { $0.path }
        let logDestinationPath = aLogDestination.path
        providerProxy.startAudit(directories: directoryPaths, logDestination: logDestinationPath)
    }
    
    func stopAudit() {
        guard let currentConnection else {
            return
        }

        guard let providerProxy = currentConnection.remoteObjectProxyWithErrorHandler({ registerError in
            self.currentConnection?.invalidate()
            self.currentConnection = nil
        }) as? HostCommunication else {
            return
        }

        providerProxy.stopAudit()
    }
    
    func getConfig(completionHandler: @escaping (Bool, [URL], URL?) -> Void) {
        guard let currentConnection else {
            completionHandler(false, [], nil)
            return
        }

        guard let providerProxy = currentConnection.remoteObjectProxyWithErrorHandler({ registerError in
            self.currentConnection?.invalidate()
            self.currentConnection = nil
        }) as? HostCommunication else {
            completionHandler(false, [], nil)
            return
        }

        return providerProxy.getConfig { running, directories, logPath in
            let directoryURLs = directories.map({
                URL(fileURLWithPath: $0, isDirectory: true)
            })
            var logURL: URL?
            if let logPath {
                logURL = URL(fileURLWithPath: logPath, isDirectory: false)
            }
            completionHandler(running, directoryURLs, logURL)
        }
    }
}
