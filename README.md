
## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd password_manager
    ```
2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Configure Gemini API Key (Optional but Recommended):**
    *   Get an API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
    *   **Security Warning:** Do NOT hardcode your API key directly in `config/settings.py` for production or shared code. The best practice is to use environment variables.
    *   **For Development/Testing:** You can edit `config/settings.py` and replace `"YOUR_GEMINI_API_KEY"` with your actual key:
        ```python
        # password_manager/config/settings.py
        GEMINI_API_KEY = "YOUR_ACTUAL_API_KEY_HERE"
        ```
    *   If you don't provide a key, Gemini-related features will be disabled.

5.  **Run the application:**
    ```bash
    python main.py
    ```

## First Run

On the first launch, you will be prompted to set a Master Password. **Choose a strong, unique password and remember it! This password is used to encrypt and protect all your stored credentials. There is no recovery mechanism if you forget it.**

## Usage

*   **Login:** Enter your master password on subsequent launches.
*   **Dashboard:**
    *   Use the search bar to filter credentials by service or username.
    *   Click "Add New" to store a new password.
    *   Click "Generator" to open the password generation/analysis tool.
    *   Use the "User" and "Pass" buttons to copy credentials to the clipboard (clears automatically after 15 seconds).
    *   Use "Edit" and "Del" to manage existing entries.
*   **Password Generator:**
    *   Adjust length and character options.
    *   Click "Generate Locally" for a quick random password.
    *   Click "Generate via Gemini" for an AI-generated password (requires API key).
    *   Enter a password in the analysis section and click "Analyze Strength (Gemini)" for AI-powered feedback (requires API key).

## Security Notes

*   The security of your stored passwords relies heavily on the strength of your **Master Password**.
*   Encryption is handled by the `cryptography` library's Fernet implementation (symmetric encryption).
*   Master password verification uses PBKDF2HMAC with a high iteration count.
*   Clipboard clearing helps mitigate shoulder surfing or clipboard hijacker risks, but is not foolproof.
*   **Gemini API Key:** Protect your API key. Using environment variables is strongly recommended over storing it in the configuration file.

## TODO / Potential Improvements

*   Add option for different encryption algorithms or key derivation functions.
*   Implement password history tracking.
*   Add categories or tags for organizing credentials.
*   Support for importing/exporting data (securely!).
*   Two-factor authentication for the master password (e.g., via OTP).
*   More robust error handling and user feedback.
*   Custom icons and styling.
*   Packaging the application into an executable (e.g., using PyInstaller).