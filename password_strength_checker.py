import tkinter as tk
from tkinter import ttk, messagebox, font
import re
import string
import hashlib
from collections import Counter
import random
import secrets

# Initialize NLTK availability with proper error handling
NLTK_AVAILABLE = False
word_set = set()

try:
    from nltk.corpus import words
    try:
        word_set = set(words.words())
        NLTK_AVAILABLE = True
    except LookupError:
        print("NLTK words corpus not downloaded. Run nltk.download('words')")
        NLTK_AVAILABLE = False
except ImportError:
    print("NLTK not installed. Using limited dictionary checks.")
    NLTK_AVAILABLE = False
except Exception as e:
    print(f"Error initializing NLTK: {str(e)}")
    NLTK_AVAILABLE = False

# Common passwords list as fallback
COMMON_PASSWORDS = {
    'password', '123456', '12345678', '1234', 'qwerty', '12345',
    'dragon', 'baseball', 'football', 'letmein', 'monkey', 'mustang',
    'access', 'shadow', 'master', 'michael', 'superman', 'batman'
}

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Enterprise Password Strength Analyzer")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f2f5")
        
        # Custom fonts
        self.title_font = font.Font(family="Segoe UI", size=18, weight="bold")
        self.label_font = font.Font(family="Segoe UI", size=12)
        self.button_font = font.Font(family="Segoe UI", size=12, weight="bold")
        self.feedback_font = font.Font(family="Consolas", size=10)
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f2f5")
        self.style.configure("TLabel", background="#f0f2f5", font=self.label_font)
        self.style.configure("TButton", font=self.button_font, padding=6)
        self.style.configure("TEntry", padding=6)
        
        # Header
        self.header_frame = ttk.Frame(root)
        self.header_frame.pack(pady=20, padx=20, fill=tk.X)
        
        self.title_label = ttk.Label(
            self.header_frame, 
            text="Enterprise Password Strength Analyzer", 
            font=self.title_font,
            foreground="#2c3e50"
        )
        self.title_label.pack()
        
        self.subtitle_label = ttk.Label(
            self.header_frame, 
            text="Secure your accounts with strong passwords", 
            foreground="#7f8c8d"
        )
        self.subtitle_label.pack(pady=5)
        
        # Main content
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(pady=10, padx=40, fill=tk.BOTH, expand=True)
        
        # Password input
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=10)
        
        self.password_label = ttk.Label(
            self.input_frame, 
            text="Enter Password:", 
            font=self.label_font
        )
        self.password_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            self.input_frame, 
            textvariable=self.password_var, 
            show="•", 
            width=40,
            font=self.label_font
        )
        self.password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)
        
        self.show_password_var = tk.IntVar()
        self.show_password_check = ttk.Checkbutton(
            self.input_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_check.pack(side=tk.LEFT, padx=(10, 0))
        
        # Strength meter
        self.meter_frame = ttk.Frame(self.main_frame)
        self.meter_frame.pack(fill=tk.X, pady=(20, 10))
        
        self.strength_label = ttk.Label(
            self.meter_frame, 
            text="Strength: ", 
            font=self.label_font
        )
        self.strength_label.pack(side=tk.LEFT)
        
        self.strength_var = tk.StringVar(value="Very Weak")
        self.strength_value = ttk.Label(
            self.meter_frame, 
            textvariable=self.strength_var,
            font=self.label_font,
            foreground="#e74c3c"
        )
        self.strength_value.pack(side=tk.LEFT, padx=(0, 10))
        
        self.meter = ttk.Progressbar(
            self.meter_frame,
            orient=tk.HORIZONTAL,
            length=300,
            mode='determinate'
        )
        self.meter.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.meter["value"] = 0
        
        # Detailed feedback
        self.feedback_frame = ttk.LabelFrame(
            self.main_frame, 
            text="Detailed Analysis",
            padding=(15, 10)
        )
        self.feedback_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 20))
        
        self.feedback_text = tk.Text(
            self.feedback_frame,
            wrap=tk.WORD,
            height=10,
            font=self.feedback_font,
            padx=10,
            pady=10,
            bg="#ffffff",
            relief=tk.FLAT
        )
        self.feedback_text.pack(fill=tk.BOTH, expand=True)
        
        # Suggestion section
        self.suggestion_frame = ttk.LabelFrame(
            self.main_frame, 
            text="Suggested Strong Password",
            padding=(15, 10)
        )
        self.suggestion_frame.pack(fill=tk.X, pady=(0, 20))
        
        self.suggestion_var = tk.StringVar()
        self.suggestion_entry = ttk.Entry(
            self.suggestion_frame,
            textvariable=self.suggestion_var,
            font=self.feedback_font,
            state='readonly',
            foreground="#27ae60"
        )
        self.suggestion_entry.pack(fill=tk.X)
        
        # Buttons
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=10)
        
        self.copy_button = ttk.Button(
            self.button_frame,
            text="Copy Suggested Password",
            command=self.copy_suggestion,
            state=tk.DISABLED
        )
        self.copy_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.generate_button = ttk.Button(
            self.button_frame,
            text="Generate New Password",
            command=self.generate_password
        )
        self.generate_button.pack(side=tk.RIGHT)
        
        # Initial feedback
        self.update_feedback("Please enter a password to analyze its strength.")
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password_strength(self, event=None):
        password = self.password_var.get()
        
        if not password:
            self.meter["value"] = 0
            self.strength_var.set("Very Weak")
            self.strength_value.config(foreground="#e74c3c")
            self.update_feedback("Please enter a password to analyze its strength.")
            self.suggestion_var.set("")
            self.copy_button.config(state=tk.DISABLED)
            return
        
        # Analyze password
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        unique_chars = len(set(password))
        common_patterns = self.check_common_patterns(password)
        is_common = self.is_common_password(password)
        entropy = self.calculate_entropy(password)
        
        # Calculate score
        score = 0
        feedback = []
        
        # Length
        if length >= 12:
            score += 30
            feedback.append("✓ Good password length (12+ characters)")
        elif length >= 8:
            score += 15
            feedback.append("✓ Minimum length (8+ characters)")
        else:
            feedback.append(f"✗ Too short (only {length} characters, minimum is 8)")
        
        # Character diversity
        char_types = 0
        if has_upper:
            char_types += 1
            score += 5
        else:
            feedback.append("✗ Missing uppercase letters")
        
        if has_lower:
            char_types += 1
            score += 5
        else:
            feedback.append("✗ Missing lowercase letters")
        
        if has_digit:
            char_types += 1
            score += 5
        else:
            feedback.append("✗ Missing numbers")
        
        if has_special:
            char_types += 1
            score += 5
            feedback.append("✓ Contains special characters")
        else:
            feedback.append("✗ Missing special characters")
        
        if char_types >= 3:
            score += 10
            feedback.append("✓ Good character diversity")
        else:
            feedback.append("✗ Limited character diversity")
        
        # Uniqueness
        uniqueness = unique_chars / length
        if uniqueness >= 0.8:
            score += 10
            feedback.append("✓ High character uniqueness")
        elif uniqueness >= 0.5:
            score += 5
            feedback.append("✓ Moderate character uniqueness")
        else:
            feedback.append("✗ Low character uniqueness (many repeated characters)")
        
        # Common patterns
        if common_patterns:
            score -= 10 * len(common_patterns)
            for pattern in common_patterns:
                feedback.append(f"✗ Contains common pattern: {pattern}")
        else:
            score += 10
            feedback.append("✓ No obvious common patterns detected")
        
        # Dictionary words
        if is_common:
            score -= 20
            feedback.append("✗ Common password or dictionary word detected")
        else:
            score += 10
            feedback.append("✓ Not a common password or dictionary word")
        
        # Entropy
        if entropy >= 80:
            score += 20
            feedback.append(f"✓ Excellent entropy ({entropy:.1f} bits)")
        elif entropy >= 60:
            score += 15
            feedback.append(f"✓ Good entropy ({entropy:.1f} bits)")
        elif entropy >= 40:
            score += 10
            feedback.append(f"✓ Moderate entropy ({entropy:.1f} bits)")
        else:
            feedback.append(f"✗ Low entropy ({entropy:.1f} bits)")
        
        # Cap score between 0 and 100
        score = max(0, min(100, score))
        
        # Update UI
        self.meter["value"] = score
        
        # Set strength level and color
        if score >= 80:
            strength = "Very Strong"
            color = "#27ae60"  # Green
        elif score >= 60:
            strength = "Strong"
            color = "#2ecc71"  # Light green
        elif score >= 40:
            strength = "Moderate"
            color = "#f39c12"  # Orange
        elif score >= 20:
            strength = "Weak"
            color = "#e67e22"  # Dark orange
        else:
            strength = "Very Weak"
            color = "#e74c3c"  # Red
        
        self.strength_var.set(strength)
        self.strength_value.config(foreground=color)
        
        # Update feedback
        feedback.insert(0, f"Password Analysis Report (Score: {score}/100)")
        feedback.append("\nRecommendations:")
        
        if score < 60:
            if length < 12:
                feedback.append("- Increase length to at least 12 characters")
            if not has_upper:
                feedback.append("- Add uppercase letters")
            if not has_lower:
                feedback.append("- Add lowercase letters")
            if not has_digit:
                feedback.append("- Add numbers")
            if not has_special:
                feedback.append("- Add special characters (!@#$%^&*, etc.)")
            if common_patterns:
                feedback.append("- Avoid common sequences (123, qwerty, etc.)")
            if is_common:
                feedback.append("- Avoid dictionary words and common passwords")
        
        self.update_feedback("\n".join(feedback))
        
        # Generate suggestion if password is weak
        if score < 70:
            self.generate_suggestion(password)
        else:
            self.suggestion_var.set("Your password is already strong!")
            self.copy_button.config(state=tk.DISABLED)
    
    def update_feedback(self, text):
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        self.feedback_text.insert(tk.END, text)
        
        # Apply formatting
        self.feedback_text.tag_configure("check", foreground="#27ae60")
        self.feedback_text.tag_configure("cross", foreground="#e74c3c")
        
        # Highlight ✓ and ✗
        start = "1.0"
        while True:
            pos = self.feedback_text.search("✓", start, tk.END)
            if not pos:
                break
            end = f"{pos}+1c"
            self.feedback_text.tag_add("check", pos, end)
            start = end
        
        start = "1.0"
        while True:
            pos = self.feedback_text.search("✗", start, tk.END)
            if not pos:
                break
            end = f"{pos}+1c"
            self.feedback_text.tag_add("cross", pos, end)
            start = end
        
        self.feedback_text.config(state=tk.DISABLED)
    
    def check_common_patterns(self, password):
        patterns = [
            r'1234567890',
            r'0987654321',
            r'qwertyuiop',
            r'asdfghjkl',
            r'zxcvbnm',
            r'password',
            r'iloveyou',
            r'111111',
            r'abc123',
            r'admin',
            r'welcome',
            r'sunshine',
            r'letmein',
            r'shadow',
            r'monkey',
            r'dragon',
            r'football',
            r'baseball',
            r'mustang',
            r'access',
            r'superman',
            r'batman'
        ]
        
        password_lower = password.lower()
        found_patterns = []
        
        for pattern in patterns:
            if re.search(pattern, password_lower):
                found_patterns.append(pattern)
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password_lower):
            found_patterns.append("repeated characters")
        
        # Check for keyboard walks
        keyboard_walks = [
            "qazwsxedcrfvtgbyhnujmikolp",
            "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
            "qwertyuiopasdfghjklzxcvbnm"
        ]
        
        for walk in keyboard_walks:
            if password_lower in walk or walk in password_lower:
                found_patterns.append("keyboard walk")
                break
        
        return found_patterns
    
    def is_common_password(self, password):
        # Check against common passwords
        if password.lower() in COMMON_PASSWORDS:
            return True
        
        # Check if it's a dictionary word (if NLTK is available)
        if NLTK_AVAILABLE and password.lower() in word_set:
            return True
        
        # Check for simple variations
        if password.lower()[:-1] in COMMON_PASSWORDS:
            return True
            
        return False
    
    def calculate_entropy(self, password):
        # Calculate character pool size
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(c in string.punctuation for c in password):
            pool_size += 32
        
        # Calculate entropy
        length = len(password)
        entropy = length * (pool_size ** 0.5)  # Simplified entropy calculation
        
        return entropy
    
    def generate_suggestion(self, original_password=None):
        # Determine what's missing in the original password
        missing = []
        if original_password:
            if not any(c.isupper() for c in original_password):
                missing.append("UPPER")
            if not any(c.islower() for c in original_password):
                missing.append("LOWER")
            if not any(c.isdigit() for c in original_password):
                missing.append("DIGIT")
            if not any(c in string.punctuation for c in original_password):
                missing.append("SPECIAL")
        
        # Generate a strong password
        length = max(12, len(original_password) if original_password else 16)
        chars = []
        
        # Ensure we have at least one of each required type
        if "UPPER" in missing or not original_password:
            chars.append(secrets.choice(string.ascii_uppercase))
        if "LOWER" in missing or not original_password:
            chars.append(secrets.choice(string.ascii_lowercase))
        if "DIGIT" in missing or not original_password:
            chars.append(secrets.choice(string.digits))
        if "SPECIAL" in missing or not original_password:
            chars.append(secrets.choice(string.punctuation))
        
        # Fill the rest with random characters
        all_chars = string.ascii_letters + string.digits + string.punctuation
        chars.extend(secrets.choice(all_chars) for _ in range(length - len(chars)))
        
        # Shuffle the characters
        random.shuffle(chars)
        suggested_password = ''.join(chars)
        
        self.suggestion_var.set(suggested_password)
        self.copy_button.config(state=tk.NORMAL)
    
    def generate_password(self):
        self.generate_suggestion()
        self.copy_button.config(state=tk.NORMAL)
    
    def copy_suggestion(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.suggestion_var.get())
        messagebox.showinfo("Copied", "The suggested password has been copied to clipboard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()
