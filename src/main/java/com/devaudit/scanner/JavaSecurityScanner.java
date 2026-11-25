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
package com.devaudit.scanner;

import com.devaudit.model.Vulnerability;
import com.devaudit.model.Vulnerability.CWE;
import com.devaudit.model.Vulnerability.OWASP;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java source code security scanner for DevAudit.
 * Performs static analysis to detect security vulnerabilities.
 */
public class JavaSecurityScanner {
    
    private final File sourceFile;
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();
    
    public JavaSecurityScanner(File sourceFile) {
        this.sourceFile = sourceFile;
    }
    
    /**
     * Perform security scan of the Java source file.
     *
     * @return list of detected vulnerabilities
     */
    public List<Vulnerability> scan() {
        vulnerabilities.clear();
        
        if (!sourceFile.exists() || !sourceFile.isFile()) {
            return vulnerabilities;
        }
        
        try {
            String content = new String(java.nio.file.Files.readAllBytes(sourceFile.toPath()));
            String[] lines = content.split("\\r?\\n");
            
            // Scan for various vulnerability patterns
            scanForSQLInjection(content, lines);
            scanForXSS(content, lines);
            scanForHardcodedCredentials(content, lines);
            scanForWeakCryptography(content, lines);
            scanForCommandInjection(content, lines);
            scanForPathTraversal(content, lines);
            scanForInformationExposure(content, lines);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return vulnerabilities;
    }
    
    private void scanForSQLInjection(String content, String[] lines) {
        // Pattern: direct string concatenation in SQL queries
        String sqlPattern = "(SELECT|INSERT|UPDATE|DELETE)\\s+.*\\s+(FROM|INTO|TABLE)\\s+.*\\s+((\\+|concat|||)\\s*('|\".*\\"))";
        Pattern pattern = Pattern.compile(sqlPattern, Pattern.CASE_INSENSITIVE);
       Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains("'") || lines[i].contains("\"")) {
                    vulnerabilities.add(new Vulnerability(
                        "SQL-INJ-" + System.currentTimeMillis(),
                        "HIGH",
                        "SQL Injection",
                        "Potential SQL injection via string concatenation",
                        "User input may be directly concatenated into SQL queries",
                        "Use PreparedStatement with parameterized queries",
                        getFilePath(), findLineNumber(lines, matcher))
                    );
                    break; // One finding per file
                }
            }
        }
    }
    
    private void scanForXSS(String content, String[] lines) {
        // Pattern: outputting user input without encoding
        String xssPattern = "(out\\.print|response\\.getWriter|println)\\s*\\(";
        Pattern pattern = Pattern.compile(xssPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            // Check if the output contains user-controlled data
            vulnerabilities.add(new Vulnerability(
                "XSS-" + System.currentTimeMillis(),
                "MEDIUM",
                "Cross-Site Scripting (XSS)",
                "User input may be output without proper encoding",
                "Unencoded user input in output methods can lead to XSS",
                "Use proper encoding (HTML/JS/URL) before output",
                getFilePath(), findLineNumber(lines, matcher))
            );
            break; // One finding per file
        }
    }
    
    private void scanForHardcodedCredentials(String content, String[] lines) {
        // Pattern: passwords, API keys in source code
        String credentialPattern = "(password|api.key|secret|token)\\s*[=:]\\s*(('|\").*?\\2)";
        Pattern pattern = Pattern.compile(credentialPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            vulnerabilities.add(new Vulnerability(
                "HARDCODED-" + System.currentTimeMillis(),
                "CRITICAL",
                "Hardcoded credentials detected",
                "Sensitive credentials may be hardcoded in source code",
                "Hardcoded passwords/keys are a major security risk",
                "Use environment variables or secret management services",
                getFilePath(), findLineNumber(lines, matcher))
            );
            break; // One finding per file
        }
    }
    
    private void scanForWeakCryptography(String content, String[] lines) {
        // Pattern: MD5, SHA1, DES, RC4 usage
        String[] weakAlgos = {"\\bMD5\\b", "\\bSHA-?1\\b", "\\bDES\\b", "\\bRC4\\b"};
        for (String algo : weakAlgos) {
            Pattern pattern = Pattern.compile(algo, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                vulnerabilities.add(new Vulnerability(
                    "WEAK-CRYPTO-" + System.currentTimeMillis(),
                    "MEDIUM",
                    "Weak cryptography detected",
                    "Use of weak cryptographic algorithm detected",
                    "MD5, SHA-1, DES, and RC4 are considered weak",
                    "Use SHA-256, SHA-3, or AES instead",
                    getFilePath(), findLineNumber(lines, matcher))
                );
                break; // One finding per algo type per file
            }
        }
    }
    
    private void scanForCommandInjection(String content, String[] lines) {
        // Pattern: Runtime.exec, Runtime.getRuntime().exec, ProcessBuilder
        String[] cmdPatterns = {"Runtime\\.getRuntime\\\(\\).*exec", "ProcessBuilder"};
        for (String patternStr : cmdPatterns) {
            Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(content);
            
            while (matcher.find()) {
                // Check if the command uses user input
                vulnerabilities.add(new Vulnerability(
                    "CMD-INJ-" + System.currentTimeMillis(),
                    "CRITICAL",
                    "Potential command injection",
                    "Runtime.exec or ProcessBuilder may execute user-controlled commands",
                    "Unvalidated input in command execution can lead to injection",
                    "Validate and sanitize all input, avoid Runtime.exec",
                    getFilePath(), findLineNumber(lines, matcher))
                );
                break;
            }
        }
    }
    
    private void scanForPathTraversal(String content, String[] lines) {
        // Pattern: file operations with user input, ../ patterns
        String pathPattern = "(\\.\\./|getResource|\\(getClass\\().getResource))";
        Pattern pattern = Pattern.compile(pathPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            vulnerabilities.add(new Vulnerability(
                "PATH-TRAV-" + System.currentTimeMillis(),
                "HIGH",
                "Potential path traversal",
                "File operations may allow directory traversal attacks",
                "User input used in file paths without validation",
                "Validate and normalize file paths, use whitelist-based access",
                getFilePath(), findLineNumber(lines, matcher))
            );
            break; // One finding per file
        }
    }
    
    private void scanForInformationExposure(String content, String[] lines) {
        // Pattern: stack traces, error messages exposed
        String errorPattern = "(printStackTrace|e\\.printStackTrace|getMessage)\\(\\)";
        Pattern pattern = Pattern.compile(errorPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(content);
        
        while (matcher.find()) {
            // Check context - if inside catch block, it might be intentional
            // But exposing stack traces in production is a risk
            vulnerabilities.add(new Vulnerability(
                "INFO-EXP-" + System.currentTimeMillis(),
                "MEDIUM",
                "Potential information exposure",
                "Error stack traces may be exposed to users",
                "Stack traces can reveal system details and code structure",
                "Handle errors gracefully, log internally, show generic messages to users",
                getFilePath(), findLineNumber(lines, matcher))
            );
            break; // One finding per file
        }
    }
    
    private String getFilePath() {
        return sourceFile.getAbsolutePath();
    }
    
    private int findLineNumber(String[] lines, Matcher matcher) {
        if (matcher == null || !matcher.find()) return 0;
        String matchedLine = matcher.group();
        // Simple approach: find the line containing the match
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].contains(matcher.group()) || lines[i].contains(matcher.pattern().pattern())) {
                return i + 1; // 1-indexed
            }
        }
        return 0;
    }
}