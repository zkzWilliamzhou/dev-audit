/*
 * Copyright 2024 DevAudit Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.devaudit.integration;

import com.devaudit.model.Vulnerability;
import com.devaudit.rules.SecurityRuleEngine;
import java.io.File;

/**
 * Command-line interface for DevAudit security scanning.
 * Provides easy access to security analysis from the command line.
 */
public class DevAuditCLI {
    
    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }
        
        File file = new File(args[0]);
        
        if (!file.exists()) {
            System.err.println("Error: File not found: " + file.getAbsolutePath());
            System.exit(1);
        }
        
        // Perform scan
        SecurityRuleEngine engine = new SecurityRuleEngine(file);
        List<Vulnerability> vulnerabilities = engine.scanWithPolicies();
        
        // Display results
        System.out.println("=== DevAudit Security Scan ===");
        System.out.println("File: " + file.getAbsolutePath());
        System.out.println("Vulnerabilities found: " + vulnerabilities.size());
        System.out.println();
        
        if (vulnerabilities.isEmpty()) {
            System.out.println("No security vulnerabilities detected.");
        } else {
            for (Vulnerability v : vulnerabilities) {
                System.out.println(v.toString());
                System.out.println();
            }
        }
        
        // Exit code based on severity
        boolean hasCritical = vulnerabilities.stream()
            .anyMatch(v -> v.getSeverity().equals("CRITICAL"));
        
        if (hasCritical) {
            System.exit(2); // Critical issues found
        } else {
            System.exit(0);
        }
    }
    
    private static void printUsage() {
        System.out.println("Usage: java DevAuditCLI <file_or_directory>");
        System.out.println("  Scans Java source files for security vulnerabilities.");
    }
}