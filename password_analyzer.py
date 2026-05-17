import re
import math
import string
import secrets
from typing import Dict, List, Tuple


class PasswordStrengthAnalyzer:

    def __init__(self):

        # Common weak passwords
        self.common_passwords = {
            "password", "123456", "123456789", "qwerty", "abc123",
            "111111", "12345678", "12345", "1234567", "dragon",
            "123123", "baseball", "football", "letmein", "monkey",
            "1234", "shadow", "master", "hello", "freedom",
            "whatever", "qazwsx", "trustno1", "123qwe",
            "1q2w3e4r", "zxcvbn", "123abc", "password1",
            "admin", "welcome"
        }

        # Character sets
        self.lowercase = set(string.ascii_lowercase)
        self.uppercase = set(string.ascii_uppercase)
        self.digits = set(string.digits)
        self.symbols = set(string.punctuation)

    def check_length(self, password: str) -> Tuple[int, str]:

        length = len(password)

        if length < 8:
            return 0, "Password is too short. Minimum 8 characters required."

        elif length < 12:
            return 20, "Password length is acceptable."

        elif length < 16:
            return 40, "Password length is good."

        else:
            return 50, "Password length is excellent."

    def check_complexity(self, password: str) -> Tuple[int, str, List[str]]:

        score = 0
        feedback = []
        missing_elements = []

        has_lowercase = any(character in self.lowercase for character in password)
        has_uppercase = any(character in self.uppercase for character in password)
        has_digits = any(character in self.digits for character in password)
        has_symbols = any(character in self.symbols for character in password)

        if has_lowercase:
            score += 15
        else:
            missing_elements.append("lowercase letters")

        if has_uppercase:
            score += 15
        else:
            missing_elements.append("uppercase letters")

        if has_digits:
            score += 15
        else:
            missing_elements.append("numbers")

        if has_symbols:
            score += 15
        else:
            missing_elements.append("special characters")

        if score == 60:
            feedback.append("Excellent character variety.")

        elif score >= 45:
            feedback.append("Good character variety.")

        elif score >= 30:
            feedback.append("Fair character variety.")

        else:
            feedback.append("Poor character variety.")

        return score, " ".join(feedback), missing_elements

    def check_patterns(self, password: str) -> Tuple[int, str]:

        score = 40
        feedback = []

        # Sequential patterns
        if re.search(
            r'abc|bcd|cde|def|123|234|345|456|567|678|789',
            password.lower()
        ):
            score -= 10
            feedback.append("Avoid sequential characters.")

        # Repeated characters
        if re.search(r'(.)\1\1', password):
            score -= 10
            feedback.append("Avoid repeating characters.")

        # Keyboard patterns
        if re.search(r'qwerty|asdf|zxcv', password.lower()):
            score -= 10
            feedback.append("Avoid keyboard patterns.")

        # Common passwords
        lower_password = password.lower()

        for common_password in self.common_passwords:

            if common_password in lower_password:
                score -= 20
                feedback.append("Contains common password patterns.")
                break

        if not feedback:
            feedback.append("No obvious weak patterns detected.")

        return max(score, 0), " ".join(feedback)

    def calculate_entropy(self, password: str) -> Tuple[float, str]:

        charset_size = 0

        if any(character in self.lowercase for character in password):
            charset_size += 26

        if any(character in self.uppercase for character in password):
            charset_size += 26

        if any(character in self.digits for character in password):
            charset_size += 10

        if any(character in self.symbols for character in password):
            charset_size += len(string.punctuation)

        if charset_size == 0:
            return 0, "instantly"

        entropy = len(password) * math.log2(charset_size)

        crack_time_seconds = (2 ** entropy) / 10000000000

        if crack_time_seconds < 1:
            crack_time = "less than a second"

        elif crack_time_seconds < 60:
            crack_time = f"{int(crack_time_seconds)} seconds"

        elif crack_time_seconds < 3600:
            crack_time = f"{int(crack_time_seconds / 60)} minutes"

        elif crack_time_seconds < 86400:
            crack_time = f"{int(crack_time_seconds / 3600)} hours"

        elif crack_time_seconds < 31536000:
            crack_time = f"{int(crack_time_seconds / 86400)} days"

        else:
            crack_time = f"{crack_time_seconds / 31536000:.2f} years"

        return entropy, crack_time

    def suggest_improvements(self, password: str) -> List[str]:

        suggestions = []

        if len(password) < 12:
            suggestions.append(
                f"Add at least {12 - len(password)} more characters."
            )

        if not any(character in self.lowercase for character in password):
            suggestions.append("Add lowercase letters.")

        if not any(character in self.uppercase for character in password):
            suggestions.append("Add uppercase letters.")

        if not any(character in self.digits for character in password):
            suggestions.append("Add numbers.")

        if not any(character in self.symbols for character in password):
            suggestions.append("Add special characters.")

        if re.search(r'(.)\1\1', password):
            suggestions.append("Avoid repeating characters.")

        if password.lower() in self.common_passwords:
            suggestions.append("Avoid using common passwords.")

        return suggestions

    def generate_strong_password(
        self,
        length: int = 16
    ) -> str:

        length = max(length, 12)

        all_characters = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            string.punctuation
        )

        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(string.punctuation)
        ]

        for _ in range(length - 4):
            password.append(secrets.choice(all_characters))

        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    def analyze(self, password: str) -> Dict:

        length_score, length_feedback = self.check_length(password)

        complexity_score, complexity_feedback, missing_elements = (
            self.check_complexity(password)
        )

        pattern_score, pattern_feedback = self.check_patterns(password)

        entropy, crack_time = self.calculate_entropy(password)

        total_score = min(
            100,
            length_score + complexity_score + pattern_score
        )

        if total_score < 30:
            strength = "Very Weak"
            color = "Red"

        elif total_score < 50:
            strength = "Weak"
            color = "Orange"

        elif total_score < 70:
            strength = "Fair"
            color = "Yellow"

        elif total_score < 90:
            strength = "Strong"
            color = "Green"

        else:
            strength = "Very Strong"
            color = "Dark Green"

        suggestions = self.suggest_improvements(password)

        return {
            "total_score": total_score,
            "strength": strength,
            "color": color,
            "length_feedback": length_feedback,
            "complexity_feedback": complexity_feedback,
            "pattern_feedback": pattern_feedback,
            "entropy": entropy,
            "crack_time": crack_time,
            "missing_elements": missing_elements,
            "suggestions": suggestions
        }


def main():

    analyzer = PasswordStrengthAnalyzer()

    print("=" * 50)
    print("PASSWORD STRENGTH ANALYZER")
    print("=" * 50)

    while True:

        password = input(
            "\nEnter password to analyze ('quit' to exit): "
        )

        if password.lower() == "quit":
            print("\nThank you for using Password Analyzer!")
            break

        if not password.strip():
            print("Password cannot be empty.")
            continue

        analysis = analyzer.analyze(password)

        print("\n" + "=" * 50)
        print("ANALYSIS RESULT")
        print("=" * 50)

        print(f"Password Strength : {analysis['strength']}")
        print(f"Security Score    : {analysis['total_score']}/100")
        print(f"Color Indicator   : {analysis['color']}")

        print("\nLength Analysis")
        print(f"- {analysis['length_feedback']}")

        print("\nComplexity Analysis")
        print(f"- {analysis['complexity_feedback']}")

        print("\nPattern Analysis")
        print(f"- {analysis['pattern_feedback']}")

        print("\nEntropy Information")
        print(f"- Entropy Value : {analysis['entropy']:.2f} bits")
        print(f"- Crack Time    : {analysis['crack_time']}")

        if analysis["missing_elements"]:
            print("\nMissing Elements")
            for element in analysis["missing_elements"]:
                print(f"- {element}")

        if analysis["suggestions"]:
            print("\nSuggestions")
            for suggestion in analysis["suggestions"]:
                print(f"- {suggestion}")

        if analysis["total_score"] < 70:

            user_choice = input(
                "\nGenerate a strong password? (y/n): "
            )

            if user_choice.lower() == "y":

                generated_password = (
                    analyzer.generate_strong_password()
                )

                print("\nGenerated Strong Password")
                print(generated_password)


if __name__ == "__main__":
    main()