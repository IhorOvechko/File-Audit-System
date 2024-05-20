//
//  ExtensionConnection.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 16.05.2024.
//

import Foundation

@objc protocol HostCommunication {
    func register(_ completionHandler: @escaping (Bool) -> Void)
    func getConfig(completionHandler: @escaping (Bool, [String], String?) -> Void)
    func startAudit(directories: [String], logDestination: String)
    func stopAudit()
}

@objc protocol ClientCommunication {
    func auditStopped()
}

func extensionIdentifier(from bundle: Bundle) -> String? {
    bundle.bundleIdentifier
}

func extensionMachServiceName(from bundle: Bundle) -> String? {
    let machServiceName = bundle.object(forInfoDictionaryKey: "NSEndpointSecurityMachServiceName") as? String
    return machServiceName
}
