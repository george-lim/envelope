//
//  Data+Extension.swift
//  Envelope
//
//  Created by George Lim on 2019-08-02.
//  Copyright © 2019 George Lim. All rights reserved.
//

import Foundation

extension Data {
  var hexString: String {
    return map { String(format: "%02hhx", $0) }.joined()
  }
}
