//
//  AuditSettingsViewController.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 17.05.2024.
//

import Cocoa

class AuditSettingsViewController: NSViewController {
    private var model: AuditModel!
    @IBOutlet weak var tableView: NSTableView!
    @IBOutlet weak var logDestinationControl: NSPathControl!
    @IBOutlet weak var removeDirectoriesButton: NSButton!
    @IBOutlet weak var toggleStartAuditButton: NSButton!
    @IBOutlet weak var stopsAuditOnAppTerminationCheckbox: NSButton!
    
    @IBAction func addDirectoryAction(_ sender: Any) {
        let openPanel = NSOpenPanel()
        openPanel.allowsMultipleSelection = true
        openPanel.canChooseDirectories = true
        openPanel.canCreateDirectories = true
        openPanel.canChooseFiles = false
        openPanel.begin { [unowned self] response in
            guard response == .OK, !openPanel.urls.isEmpty else {
                return
            }
            
            model.addTracking(directories: openPanel.urls)
        }
    }
    
    @IBAction func toggleStartAudit(_ sender: Any) {
        model.running.toggle()
    }
    
    @IBAction func removeDirectoriesAction(_ sender: Any) {
        model.removeTracking(indexes: tableView.selectedRowIndexes)
    }
    
    @IBAction func selectLogDestination(_ sender: NSPathControl) {
        let savePanel = NSSavePanel()
        savePanel.allowedFileTypes = ["txt"]
        if let url = sender.url {
            savePanel.directoryURL = url.deletingLastPathComponent()
            savePanel.nameFieldStringValue = url.lastPathComponent
        }
        savePanel.begin { [unowned self] response in
            guard response == .OK, let url = savePanel.url else {
                return
            }
            model.logDestination = url
        }
    }
    
    
    @IBAction func stopsAuditOnAppTerminationCheckboxAction(_ sender: NSButton) {
        model.stopsAuditOnAppTermination = sender.state == .on
    }
    
    init(model aModel: AuditModel) {
        model = aModel
        super.init(nibName: AuditSettingsViewController.classForCoder().description(), bundle: nil)
        model.notificationCenter.addObserver(forName: AuditModel.trackingDirectoriesDidChangeNotification, object: model, queue: nil) { [unowned self] _ in
            updateTableView()
            updateToggleStartAuditButton()
        }
        
        model.notificationCenter.addObserver(forName: AuditModel.logDestinationDidChangeNotification, object: model, queue: nil) { [unowned self] _ in
            updateLogDestinationControl()
            updateToggleStartAuditButton()
        }
        
        model.notificationCenter.addObserver(forName: AuditModel.runningDidChangeNotification, object: model, queue: nil) { [unowned self] _ in
            updateToggleStartAuditButton()
        }
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        updateTableView()
        updateLogDestinationControl()
        updateToggleStartAuditButton()
        stopsAuditOnAppTerminationCheckbox.state = model.stopsAuditOnAppTermination ? .on : .off
    }
    
    private func updateTableView() {
        tableView.reloadData()
        updateRemoveDirectoriesButton()
    }
    
    private func updateRemoveDirectoriesButton() {
        removeDirectoriesButton.isEnabled = !tableView.selectedRowIndexes.isEmpty
    }
    
    private func updateLogDestinationControl() {
        logDestinationControl.url = model.logDestination
    }
    
    private func updateToggleStartAuditButton() {
        toggleStartAuditButton.isEnabled = model.running || model.canRun
        toggleStartAuditButton.title = model.running ? NSLocalizedString("Stop audit", comment: "The title of a button stopping audit") : NSLocalizedString("Start audit", comment: "The title of a button starting audit")
    }
}

extension AuditSettingsViewController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return model.trackingDirectories.count
    }
    
    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard model.trackingDirectories.indices.contains(row), let view = tableView.makeView(withIdentifier: tableColumn!.identifier, owner: self) as? NSTableCellView else {
            return nil
        }
        view.textField?.stringValue = model.trackingDirectories[row].path
        
        return view
    }
    
    func tableViewSelectionDidChange(_ notification: Notification) {
        updateRemoveDirectoriesButton()
    }
}
