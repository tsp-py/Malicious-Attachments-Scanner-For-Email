from helpers.imports import *
from config.patterns import patterns, suspicious_indicators
from io import BytesIO
import json
import requests
from typing import Dict, List, Any, Union

class SecurityScanner:
    def __init__(self):
        self.patterns = patterns
        self.suspicious_indicators = suspicious_indicators

    def check_generic_malicious(self, content: str) -> bool:
        """
        Checks content for suspicious indicators or patterns.
        """
        try:
            if any(indicator in content for indicator in self.suspicious_indicators):
                return True
            for name, pattern in self.patterns.items():
                if re.search(pattern, content):
                    print(f"Pattern match detected: {name}")
                    return True
            return False
        except Exception as e:
            print(f"Error processing content: {e}")
            return False

    def check_attachment_malicious(self, filename: str, file_content: bytes) -> bool:
        """
        Scans attachments for malicious indicators based on their type and pattern matching.
        """
        if file_content is None:
            return False

        # Check for double extensions
        if self.check_double_extension(filename):
            return True

        # Decode file content into a string for scanning
        try:
            content = file_content.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Error decoding file content: {e}")
            return False

        return self.check_generic_malicious(content)

    def check_double_extension(self, filename: str) -> bool:
        """
        Check if filename has suspicious double extensions
        """
        parts = filename.split('.')
        dangerous_extensions = ['exe', 'scr', 'js', 'vbs', 'bat', 'cmd', 'pif', 'com', 'dll']
        if len(parts) > 2:
            if parts[-1].lower() in dangerous_extensions or parts[-2].lower() in dangerous_extensions:
                return True
        return False

    def check_message_content(self, message: str) -> Dict[str, Any]:
        """
        Analyze message content for potential security threats
        """
        threats = []
        is_malicious = False

        # Check for suspicious patterns in the message
        if self.check_generic_malicious(message):
            is_malicious = True
            threats.append("Suspicious pattern detected in message")

        # Check for URLs in the message
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
        if urls:
            threats.append("Contains URLs - potential phishing risk")

        return {
            "is_malicious": is_malicious,
            "threats": threats,
            "urls_found": urls
        }

class EmailScanner(SecurityScanner):
    def scan_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan email content and attachments for security threats
        """
        results = {
            "is_malicious": False,
            "threats": [],
            "attachments_scan": []
        }

        # Check email content
        content_scan = self.check_message_content(str(email_data.get("message", "")))
        results["threats"].extend(content_scan["threats"])
        results["is_malicious"] = content_scan["is_malicious"]

        # Check attachments
        for attachment in email_data.get("attachments", []):
            attachment_result = {
                "filename": attachment["filename"],
                "is_malicious": attachment["attachment_safe"] == "Malicious"
            }
            results["attachments_scan"].append(attachment_result)
            if attachment_result["is_malicious"]:
                results["is_malicious"] = True
                results["threats"].append(f"Malicious attachment found: {attachment['filename']}")

        return results

class InstagramScanner(SecurityScanner):
    def scan_instagram_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan Instagram message content and media for security threats
        """
        results = {
            "is_malicious": False,
            "threats": [],
            "media_scan": []
        }

        # Check message content
        content_scan = self.check_message_content(message_data.get("text", ""))
        results["threats"].extend(content_scan["threats"])
        results["is_malicious"] = content_scan["is_malicious"]

        # Check media attachments
        for media in message_data.get("media", []):
            media_result = {
                "media_type": media.get("type"),
                "is_malicious": False
            }
            
            # Check media URL or content if available
            if media.get("url"):
                content_scan = self.check_message_content(media["url"])
                if content_scan["is_malicious"]:
                    media_result["is_malicious"] = True
                    results["threats"].append(f"Suspicious media content detected")
            
            results["media_scan"].append(media_result)
            if media_result["is_malicious"]:
                results["is_malicious"] = True

        return results

class WhatsAppScanner(SecurityScanner):
    def scan_whatsapp_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan WhatsApp message content and media for security threats
        """
        results = {
            "is_malicious": False,
            "threats": [],
            "media_scan": []
        }

        # Check message content
        content_scan = self.check_message_content(message_data.get("text", ""))
        results["threats"].extend(content_scan["threats"])
        results["is_malicious"] = content_scan["is_malicious"]

        # Check media attachments
        for media in message_data.get("media", []):
            media_result = {
                "media_type": media.get("type"),
                "filename": media.get("filename"),
                "is_malicious": False
            }
            
            # Check media content if available
            if media.get("content"):
                if self.check_attachment_malicious(media.get("filename", ""), media["content"]):
                    media_result["is_malicious"] = True
                    results["threats"].append(f"Suspicious media content detected: {media.get('filename')}")
            
            results["media_scan"].append(media_result)
            if media_result["is_malicious"]:
                results["is_malicious"] = True

        return results
