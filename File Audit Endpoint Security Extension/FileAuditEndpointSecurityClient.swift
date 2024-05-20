//
//  FileAuditEndpointSecurityClient.swift
//  File Audit Endpoint Security Extension
//
//  Created by Ihor Ovechko on 17.05.2024.
//

import Foundation
import EndpointSecurity

protocol FileAuditEndpointSecurityClientDelegate : AnyObject {
    func endpointSecurityDidStop(_ client: FileAuditEndpointSecurityClient)
}

class FileAuditEndpointSecurityClient {
    private (set) var trackingDirectories = Array<String>()
    private (set) var logDestination: String? {
        didSet {
            guard oldValue != logDestination else {
                return
            }
            try? logFileHandle?.close()
            if let logDestination {
                if !FileManager.default.fileExists(atPath: logDestination) {
                    FileManager.default.createFile(atPath: logDestination, contents: nil)
                } else if !FileManager.default.isWritableFile(atPath: logDestination) {
                    try? FileManager.default.removeItem(atPath: logDestination)
                    FileManager.default.createFile(atPath: logDestination, contents: nil)
                }
                logFileHandle = FileHandle(forWritingAtPath: logDestination)
                logFileHandle?.seekToEndOfFile()
            }
        }
    }
    private var logFileHandle: FileHandle?
    private var client: OpaquePointer?
    var running: Bool { client != nil }
    weak var delegate: FileAuditEndpointSecurityClientDelegate?
    
    func startAudit(directories: [String], logDestination aLogDestination: String) {
        trackingDirectories = directories
        logDestination = aLogDestination
        if client == nil {
            startClient()
        }
    }
    
    func stopAudit() {
        stopClient()
    }
    
    private func startClient() {
        var aClient: OpaquePointer?
        let res = es_new_client(&aClient) { [weak self] (client, message) in
            self?.handle(message)
        }

        guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let aClient else {
            exit(EXIT_FAILURE)
        }
        
        let events = [ES_EVENT_TYPE_NOTIFY_ACCESS, ES_EVENT_TYPE_NOTIFY_CLONE, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_COPYFILE, ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR, ES_EVENT_TYPE_NOTIFY_DUP, ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FCNTL, ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE, ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_FSGETPATH, ES_EVENT_TYPE_NOTIFY_GETATTRLIST, ES_EVENT_TYPE_NOTIFY_GETEXTATTR, ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_LISTEXTATTR, ES_EVENT_TYPE_NOTIFY_LOOKUP, ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_READDIR, ES_EVENT_TYPE_NOTIFY_READLINK, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_SEARCHFS, ES_EVENT_TYPE_NOTIFY_SETACL, ES_EVENT_TYPE_NOTIFY_SETATTRLIST, ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_NOTIFY_SETFLAGS, ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_STAT, ES_EVENT_TYPE_NOTIFY_TRUNCATE, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_UTIMES, ES_EVENT_TYPE_NOTIFY_WRITE]

        let subres = es_subscribe(aClient, events, UInt32(events.count))
        guard subres == ES_RETURN_SUCCESS else {
            exit(EXIT_FAILURE)
        }
        
        client = aClient
    }
    
    private func stopClient() {
        if let client {
            es_unsubscribe_all(client)
            es_delete_client(client)
        }
        client = nil
        delegate?.endpointSecurityDidStop(self)
    }
    
    private func handle(_ message: UnsafePointer<es_message_t>) {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            if let eventPath = string(from: message.pointee.event.access.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Checking of a file's access permission", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_CLONE:
            if let eventPath = string(from: message.pointee.event.clone.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Clone from", message: message)
            }
            if let eventPath = string(from: message.pointee.event.clone.target_dir.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: string(from: message.pointee.event.clone.target_name) ?? fileName(of: eventPath), type: "Clone to", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            if let eventPath = string(from: message.pointee.event.close.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Close", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            if let eventPath = string(from: message.pointee.event.copyfile.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Copy from", message: message)
            }
            if let eventPath = string(from: message.pointee.event.copyfile.target_dir.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: string(from: message.pointee.event.copyfile.target_name) ?? fileName(of: eventPath), type: "Copy to", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            if message.pointee.event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE, let eventPath = string(from: message.pointee.event.create.destination.existing_file.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Creation", message: message)
            } else if message.pointee.event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH, let eventPath = string(from: message.pointee.event.create.destination.new_path.dir.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: string(from: message.pointee.event.create.destination.new_path.filename) ?? fileName(of: eventPath), type: "Creation", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            if let eventPath = string(from: message.pointee.event.deleteextattr.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Delete extended attributes", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_DUP:
            if let eventPath = string(from: message.pointee.event.dup.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Duplicate file descriptor", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            if let eventPath = string(from: message.pointee.event.exchangedata.file1.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Exchange data", message: message)
            }
            if let eventPath = string(from: message.pointee.event.exchangedata.file2.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Exchange data", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            if let eventPath = string(from: message.pointee.event.exec.dyld_exec_path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Execute", message: message)
            } else if let eventPath = string(from: message.pointee.event.exec.target.pointee.executable.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Execute", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            if let eventPath = string(from: message.pointee.event.fcntl.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Manipulate file descriptor", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
            if let eventPath = string(from: message.pointee.event.file_provider_materialize.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Materialization of a file provider", message: message)
            }
            if let eventPath = string(from: message.pointee.event.file_provider_materialize.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Materialization of a file provider", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
            if let eventPath = string(from: message.pointee.event.file_provider_update.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Update to a file provider", message: message)
            }
            if let eventPath = string(from: message.pointee.event.file_provider_update.target_path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Update to a file provider", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_FORK:
            if let eventPath = string(from: message.pointee.event.fork.child.pointee.executable.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Forking", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            if let eventPath = string(from: message.pointee.event.fsgetpath.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Retrieval of a file-system path", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            if let eventPath = string(from: message.pointee.event.getattrlist.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Retrieval of attributes", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            if let eventPath = string(from: message.pointee.event.getextattr.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Retrieval of an extended attribute", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_LINK:
            if let eventPath = string(from: message.pointee.event.link.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Creation of a hard link from", message: message)
            }
            if let eventPath = string(from: message.pointee.event.link.target_dir.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: string(from: message.pointee.event.link.target_filename) ?? fileName(of: eventPath), type: "Creation of a hard link to", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            if let eventPath = string(from: message.pointee.event.listextattr.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Retrieval of multiple extended attributes", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            if let eventPath = string(from: message.pointee.event.lookup.source_dir.pointee.path), isPathTracked(eventPath) {
                var relativeTargetFilename: String?
                if let relativeTarget = string(from: message.pointee.event.lookup.relative_target) {
                    relativeTargetFilename = fileName(of: relativeTarget)
                }
                logAudit(filename: relativeTargetFilename ?? fileName(of: eventPath), type: "Lookup of a file's path", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_MMAP:
            if let eventPath = string(from: message.pointee.event.mmap.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Mapping of memory", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            if let eventPath = string(from: message.pointee.event.open.file.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Read", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_READDIR:
            if let eventPath = string(from: message.pointee.event.readdir.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Reading of a file-system directory", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_READLINK:
            if let eventPath = string(from: message.pointee.event.readlink.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Reading of a symbolic link", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            if let eventPath = string(from: message.pointee.event.rename.source.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Renaming from", message: message)
            }
            if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE, let eventPath = string(from: message.pointee.event.rename.destination.existing_file.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Renaming to", message: message)
            } else if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH, let eventPath = string(from: message.pointee.event.rename.destination.new_path.dir.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: string(from: message.pointee.event.rename.destination.new_path.filename) ?? fileName(of: eventPath), type: "Renaming to", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            if let eventPath = string(from: message.pointee.event.searchfs.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Search operation", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETACL:
            if let eventPath = string(from: message.pointee.event.setacl.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting access control list", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            if let eventPath = string(from: message.pointee.event.setattrlist.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting of an attribute", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            if let eventPath = string(from: message.pointee.event.setextattr.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting of an extended attribute", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            if let eventPath = string(from: message.pointee.event.setflags.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting of flags", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            if let eventPath = string(from: message.pointee.event.setmode.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting of mode", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            if let eventPath = string(from: message.pointee.event.setowner.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Setting owner", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_STAT:
            if let eventPath = string(from: message.pointee.event.stat.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Retrieval of a file's status", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            if let eventPath = string(from: message.pointee.event.truncate.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Truncation", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            if let eventPath = string(from: message.pointee.event.unlink.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Deletion", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            if let eventPath = string(from: message.pointee.event.utimes.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Change to a file’s access time or modification time", message: message)
            }
        case ES_EVENT_TYPE_NOTIFY_WRITE:
            if let eventPath = string(from: message.pointee.event.write.target.pointee.path), isPathTracked(eventPath) {
                logAudit(filename: fileName(of: eventPath), type: "Writing", message: message)
            }
        default:
            break
        }
    }
    
    private func string(from token: es_string_token_t) -> String? {
        if token.length != 0 && token.data != nil {
            return String(cString: token.data, encoding: .utf8)
        } else {
            return nil
        }
    }
    
    private func fileName(of path: String) -> String {
        (path as NSString).lastPathComponent
    }
    
    private func isPathTracked(_ path: String) -> Bool {
        trackingDirectories.contains(where: { directoryPath in
            if let directoryRange = path.range(of: directoryPath, options: .anchored), directoryRange.lowerBound == path.startIndex && directoryRange.upperBound > path.startIndex {
                return directoryRange.upperBound == path.endIndex || path[directoryRange.upperBound] == "/"
            }
            return false
        })
    }
    
    private func timestamp(of message: UnsafePointer<es_message_t>) -> Int {
        Int(message.pointee.time.tv_sec * 1000) + Int(message.pointee.time.tv_nsec / (1000 * 1000))
    }
    
    private func user(of process: UnsafeMutablePointer<es_process_t>) -> String {
        guard let pw_name = getpwuid(audit_token_to_euid(process.pointee.audit_token))?.pointee.pw_name else {
            return ""
        }
        return String(cString: pw_name)
    }
    
    private func processID(of process: UnsafeMutablePointer<es_process_t>) -> pid_t {
        process.pointee.ppid
    }
    
    private func logAudit(filename: String, type: String, message: UnsafePointer<es_message_t>) {
        guard let logFileHandle else {
            stopClient()
            return
        }
        let logMessage = String("File name: \(filename) timestamp: \(timestamp(of: message)) user: \(user(of: message.pointee.process)) process ID: \(processID(of: message.pointee.process)) type: \(type)\n")
        if let logData = logMessage.data(using: .utf8) {
            logFileHandle.write(logData)
        }
    }
}
