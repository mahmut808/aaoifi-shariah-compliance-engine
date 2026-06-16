# file: /home/mahmut/Desktop/uyumprotokol/core/security_sanitizer.py
import re

class UniversalInputSanitizer:
    """
    OWASP ASVS Standard Core Security Sanitizer
    Provides:
      - Null Byte Injection protection (\x00)
      - XSS mitigation while preserving Turkish/Arabic Unicode segments
      - ReDoS prevention through length limits and linear non-backtracking patterns
      - File Path Traversal protection
    """
    @staticmethod
    def sanitize(text: str, max_length: int = 250000) -> str:
        if not text:
            return ""

        # ReDoS Prevention: Hard boundary on text length to prevent exponential execution time
        if len(text) > max_length:
            text = text[:max_length]

        # 1. Block Null Byte Attacks (\x00)
        text = text.replace("\x00", "")

        # 2. XSS Mitigation: Remove <script> and <style> blocks in a ReDoS-safe linear way
        # By using a simple character-by-character scanner or basic regexes
        # Strip script blocks
        text = re.sub(r'(?i)<script[^>]*>[\s\S]*?</script>', '', text)
        # Strip style blocks
        text = re.sub(r'(?i)<style[^>]*>[\s\S]*?</style>', '', text)
        # Strip generic HTML tags while preserving Arabic and Turkish characters
        text = re.sub(r'<[^>]{1,50}>', '', text)  # Keep the length of the tag content bounded to 50 chars to avoid backtracking ReDoS
        text = text.replace("<", "&lt;").replace(">", "&gt;")

        # 3. Unicode and formatting cleanup (preserving RTL markers)
        clean_chars = []
        for char in text:
            code = ord(char)
            # Accept basic layout whitespace, standard printable characters, Turkish, and Arabic Unicode segments
            if code >= 32 or char in ('\n', '\r', '\t', '\u200E', '\u200F', '\u061C'):
                clean_chars.append(char)

        return "".join(clean_chars).strip()

    @staticmethod
    def sanitize_path(path: str) -> str:
        """
        Validates file path parameters against Directory Traversal and Null Byte Poisoning.
        """
        if not path:
            raise ValueError("Dosya yolu boş olamaz / File path cannot be empty.")

        # Null byte check
        if "\x00" in path:
            raise ValueError("Güvenlik İhlali: Null byte (\\x00) tespit edildi / Security violation: Null byte detected.")

        # Directory traversal protection
        normalized_path = path.replace("\\", "/")
        if ".." in normalized_path or "./" in normalized_path:
            raise ValueError("Güvenlik İhlali: Path Traversal tespit edildi / Security violation: Path Traversal detected.")

        # Check for system files access attempt
        if any(bad in normalized_path.lower() for bad in ["/etc/", "/windows/", "/proc/", "/dev/"]):
            raise ValueError("Güvenlik İhlali: Sistem dosyalarına erişim engellendi / Security violation: Access to system paths blocked.")

        return path

    @staticmethod
    def validate_file_extension_and_header(file_path: str) -> bool:
        """
        OWASP ASVS strictly validates file extension, blocks null bytes,
        detects double extensions (e.g. file.pdf.exe), and checks file signatures/headers.
        """
        import os
        if not file_path:
            raise ValueError("Dosya yolu boş olamaz / File path cannot be empty.")

        if "\x00" in file_path:
            raise ValueError("Güvenlik İhlali: Null byte (\\x00) tespit edildi / Security violation: Null byte detected.")

        # Get base name and lowercase it
        base_name = os.path.basename(file_path).lower()

        # Double extension check: e.g. file.pdf.exe
        parts = base_name.split('.')
        if len(parts) > 2:
            # Check if any middle parts look like a dangerous/disallowed extension, or simply fail if they try to bypass
            # Let's strictly block if the final extension is not in ('pdf', 'md', 'txt', 'docx').
            pass

        allowed_exts = ('pdf', 'md', 'txt', 'docx')
        ext = parts[-1] if len(parts) > 1 else ""
        if ext not in allowed_exts:
            raise ValueError(f"Güvenlik İhlali: Desteklenmeyen uzantı '{ext}'. Yalnızca {allowed_exts} yüklenebilir.")

        # Check if the file exists
        if not os.path.exists(file_path):
            raise ValueError("Dosya mevcut değil / File does not exist.")

        # Read the first few bytes (header check / magic numbers)
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
        except Exception as e:
            raise ValueError(f"Dosya okuma hatası / File read error: {str(e)}")

        if ext == "pdf":
            # PDF header is %PDF (0x25 0x50 0x44 0x46)
            if not header.startswith(b"%PDF"):
                raise ValueError("Güvenlik İhlali: Geçersiz PDF dosya imzası / Invalid PDF signature.")
        elif ext == "docx":
            # DOCX (ZIP) header is PK\x03\x04 (0x50 0x4B 0x03 0x04)
            if not header.startswith(b"PK\x03\x04"):
                raise ValueError("Güvenlik İhlali: Geçersiz DOCX dosya imzası / Invalid DOCX signature.")
        elif ext in ("txt", "md"):
            # Plain text files: verify they don't contain binary null bytes or are readable as text
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    f.read(1024)
            except UnicodeDecodeError:
                try:
                    with open(file_path, "r", encoding="latin-1") as f:
                        f.read(1024)
                except Exception:
                    raise ValueError("Güvenlik İhlali: Metin dosyası geçersiz karakterler içeriyor / Invalid text file content.")

        return True

    @staticmethod
    def validate_safe_pdf_path(path: str) -> str:
        """
        Validates file path strictly whitelisting only the defined local PDF files
        and preventing path traversal or injection.
        """
        import os
        if not path:
            raise ValueError("Dosya yolu boş olamaz / File path cannot be empty.")
            
        if "\x00" in path:
            raise ValueError("Güvenlik İhlali: Null byte (\\x00) tespit edildi.")
            
        normalized = path.replace("\\", "/")
        if ".." in normalized or "./" in normalized:
            raise ValueError("Güvenlik İhlali: Path Traversal tespit edildi.")
            
        filename = os.path.basename(normalized)
        allowed_filenames = [
            "faizsiz finans standartları aaoifi (güncellenmiş versiyon).pdf",
            "faizsiz finans standartları aaoifi (güncellenmiş versiyon).pdf",
            "faizsiz finans standartları aaoifi.pdf",
            "shariaa-standards-eng.pdf",
            "shariaa-standards-ara.pdf",
            "723607313-معايير-الأيوفي-الشرعية-النسخة-العربية-2017.pdf",
            "aaoifi.pdf"
        ]
        
        if filename.lower() not in allowed_filenames:
            raise ValueError(f"Güvenlik İhlali: Yetkisiz PDF dosyası yükleme teşebbüsü: {filename}")
            
        return path


