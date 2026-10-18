#!/usr/bin/env python3
"""
ReverseBug Sample Test APK Generator
Generates a realistic, synthetically vulnerable Android APK package
specifically designed for verifying ReverseBug static analysis, secrets detection,
decompilation, evidence graph synthesis, and AI agent investigation.

Usage:
    python scripts/generate_test_apk.py [output_path]
"""

import sys
import os
import zipfile
import struct
from pathlib import Path

MANIFEST_CONTENT = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.reversebug.vulnerableapp"
    android:versionCode="100"
    android:versionName="1.0.0">

    <!-- Sensitive and Excessive Permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:label="ReverseBug Insecure Demo"
        android:theme="@android:style/Theme.NoTitleBar">

        <!-- Main Launcher Activity -->
        <activity
            android:name="com.reversebug.vulnerableapp.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported Sensitive Activity without permission -->
        <activity
            android:name="com.reversebug.vulnerableapp.PaymentGatewayActivity"
            android:exported="true"
            android:label="Insecure Payment Gateway">
            <intent-filter>
                <action android:name="com.reversebug.action.PROCESS_PAYMENT" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>

        <!-- Exported Vulnerable Broadcast Receiver -->
        <receiver
            android:name="com.reversebug.vulnerableapp.InternalCommandReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.reversebug.action.EXECUTE_COMMAND" />
            </intent-filter>
        </receiver>

        <!-- Insecure Content Provider with exported=true -->
        <provider
            android:name="com.reversebug.vulnerableapp.UserCredentialsProvider"
            android:authorities="com.reversebug.vulnerableapp.userdata"
            android:exported="true" />

        <!-- Background Sync Service -->
        <service
            android:name="com.reversebug.vulnerableapp.TelemetryUploadService"
            android:exported="false" />
    </application>
</manifest>
"""

NETWORK_SECURITY_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Insecure: Permitting Cleartext HTTP Traffic across all domains -->
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <!-- Insecure: Trusting User Installed CA Certificates in Production -->
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""

APP_CONFIG_JSON = """{
  "environment": "production",
  "api_gateway": "http://api.insecure-backend.reversebug.internal",
  "logging_level": "DEBUG",
  "encryption_cipher": "AES/ECB/PKCS5Padding",
  "hardcoded_credentials": {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "stripe_publishable_key": "pk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz123456789",
    "database_connection_url": "postgres://api_admin:SuperSecretDatabaseP@ss123!@db-prod.internal:5432/customers"
  }
}
"""

def create_synthetic_dex():
    """Builds a DEX header containing embedded bytecode strings and patterns."""
    magic = b"dex\n035\0"
    checksum = b"\x00\x00\x00\x00"
    signature = b"\x00" * 20
    
    # Embedded strings with OWASP vulnerabilities and hardcoded secrets
    payload_strings = [
        b"Lcom/reversebug/vulnerableapp/MainActivity;",
        b"Lcom/reversebug/vulnerableapp/PaymentGatewayActivity;",
        b"Lcom/reversebug/vulnerableapp/CryptoManager;",
        b"AKIAIOSFODNN7EXAMPLE",
        b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        b"ghp_ABC1234567890abcdefghijklmnopqrstuvwxyz",
        b"AIzaSyD-fakeGoogleApiKey1234567890abcdef",
        b"postgres://api_admin:SuperSecretDatabaseP@ss123!@db-prod.internal:5432/customers",
        b"AES/ECB/PKCS5Padding",
        b"TrustAllCertificates",
        b"ALLOW_ALL_HOSTNAME_VERIFIER",
        b"SELECT * FROM users WHERE username = '\" + input + \"' AND password = '\" + pass + \"'\"",
        b"Runtime.getRuntime().exec(command);",
        b"getSharedPreferences(\"user_credentials\", MODE_WORLD_READABLE);",
        b"Cipher.getInstance(\"DES\");",
    ]
    
    body = b"\n".join(payload_strings)
    file_size = 112 + len(body)
    header = magic + checksum + signature + struct.pack("<I", file_size) + (b"\x00" * 80)
    return header + body

def generate_apk(output_path: str = "test-vulnerable-app.apk"):
    target = Path(output_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Packaging test APK to: {target}")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", MANIFEST_CONTENT)
        z.writestr("res/xml/network_security_config.xml", NETWORK_SECURITY_CONFIG)
        z.writestr("assets/config/app_config.json", APP_CONFIG_JSON)
        z.writestr("classes.dex", create_synthetic_dex())
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: ReverseBug-Test-Suite\n")
        z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\nSHA-256-Digest-Manifest: dummy\n")
    
    size_kb = target.stat().st_size / 1024
    print(f"[+] Successfully generated test APK ({size_kb:.1f} KB)")
    print(f"[+] Path: {target}")
    return str(target)

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test-vulnerable-app.apk"
    generate_apk(out)
