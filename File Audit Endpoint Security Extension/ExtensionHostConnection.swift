//
//  ExtensionHostConnection.swift
//  File Audit Endpoint Security Extension
//
//  Created by Ihor Ovechko on 17.05.2024.
//

import Cocoa

class ExtensionHostConnection: NSObject {
    var listener: NSXPCListener?
    var currentConnection: NSXPCConnection?
    static let shared = ExtensionHostConnection()
    var endpointSecurityClient = FileAuditEndpointSecurityClient()
    
    func startListener() {
        guard let machServiceName = extensionMachServiceName(from: Bundle.main) else {
            return
        }
        
        let listener = NSXPCListener(machServiceName: machServiceName)
        listener.delegate = self
        listener.resume()
        self.listener = listener
        endpointSecurityClient.delegate = self
    }
    
    private func auditStopped() {

        guard let connection = currentConnection else {
            return
        }

        guard let appProxy = connection.remoteObjectProxyWithErrorHandler({ promptError in
            self.currentConnection = nil
        }) as? ClientCommunication else {
            return
        }

        appProxy.auditStopped()
    }
}

extension ExtensionHostConnection: NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: HostCommunication.self)
        newConnection.exportedObject = self
        newConnection.remoteObjectInterface = NSXPCInterface(with: ClientCommunication.self)
        newConnection.invalidationHandler = {
            self.currentConnection = nil
        }
        newConnection.interruptionHandler = {
            self.currentConnection = nil
        }
        currentConnection = newConnection
        newConnection.resume()
        return true
    }
}

extension ExtensionHostConnection: HostCommunication {
    func register(_ completionHandler: @escaping (Bool) -> Void) {
        completionHandler(true)
    }
    
    func getConfig(completionHandler: @escaping (Bool, [String], String?) -> Void) {
        completionHandler(endpointSecurityClient.running, endpointSecurityClient.trackingDirectories, endpointSecurityClient.logDestination)
    }
    
    func startAudit(directories: [String], logDestination: String) {
        endpointSecurityClient.startAudit(directories: directories, logDestination: logDestination)
    }
    
    func stopAudit() {
        endpointSecurityClient.stopAudit()
    }
}

extension ExtensionHostConnection : FileAuditEndpointSecurityClientDelegate {
    func endpointSecurityDidStop(_ client: FileAuditEndpointSecurityClient) {
        auditStopped()
    }
}
