//
//  UserDefaultsStorage.swift
//  File Audit System
//
//  Created by Ihor Ovechko on 19.05.2024.
//

import Foundation

@propertyWrapper
struct UserDefaultsStorage<T> {
    private let key: String
    private let defaultValue: T
    
    init(key: String, defaultValue: T) {
        self.key = key
        self.defaultValue = defaultValue
    }
    
    var wrappedValue: T {
        get {
            UserDefaults.standard.object(forKey: key) as? T ?? defaultValue
        }
        set {
            UserDefaults.standard.set(newValue, forKey: key)
        }
    }
}
