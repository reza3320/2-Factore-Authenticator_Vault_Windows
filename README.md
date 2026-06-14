# Win2FA - Secure Offline 2FA Authenticator

Win2FA is a highly-secure, 100% offline Two-Factor Authentication (2FA) desktop application for Windows. It allows you to securely store your 2FA accounts and generate Time-based One-Time Passwords (TOTP) locally on your PC.

The application includes a local Google Authenticator migration decoder, allowing you to easily import all your existing accounts directly from exported Google Authenticator QR code screenshots in bulk.


<table align="center" border="0">
  <tr>
    <td align="center" valign="middle">
      <img src="https://github.com/user-attachments/assets/5effd85f-de23-49e3-bc2c-f6d39b3e00cd" height="350" alt="Main Window" />
    </td>
    <td align="center" valign="middle">
      <img src="https://github.com/user-attachments/assets/33125eff-b616-4fc4-983f-508b1bdf3a77" height="350" alt="Tray Window" />
    </td>
  </tr>
</table>


## Features

- **100% Offline & Air-Gapped:** Zero network capability, no analytics, and no cloud syncing. Your data never leaves your machine.
- **On-Disk DPAPI Encryption:** Your secrets database is encrypted on disk using the Windows Data Protection API (DPAPI). Encryption keys are tied directly to your active Windows user profile, meaning the database cannot be decrypted on other computers or by other user accounts.
- **Bulk Google Authenticator Import:** Simply select a QR code screenshot exported from Google Authenticator to instantly import and decode all your accounts locally.
- **Add Single Keys Manually:** Easily add single accounts by manually entering the Issuer, Account Name, and Base32 Secret Key.
- **System Tray Integration:** Minimize the app to the system tray to keep it running silently in the background. Right-click the tray icon to toggle "Start at Startup" or exit.
- **Dynamic Theme Sync:** Fully supports Light and Dark modes, with an option to synchronize with your Windows system and taskbar theme dynamically.
- **Tactile Copy Feedback:** Click on any authenticator card to instantly copy the code to your clipboard.

## Installation

You can download the pre-compiled, standalone, single-file executable from the **[Releases](../../releases)** page.

1. Download `win-2fa-authenticator.exe`.
2. Run the executable. It is fully self-contained and requires no installation.

## How to Build

If you prefer to compile the application yourself from the source code, make sure you have the **.NET 8.0 SDK** installed on your Windows machine.

1. Clone or download this repository.
2. Open a PowerShell or CMD terminal in the project folder.
3. Run the following command to restore packages and publish a self-contained, single-file executable:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -p:IncludeNativeLibrariesForSelfExtract=true
```

4. Once the compilation completes, your standalone executable will be located in:
   `bin\Release\net8.0-windows\win-x64\publish\win-2fa-authenticator.exe`

## Technical Details

- **Language & Framework:** C# .NET 8.0 WPF
- **Encryption:** Windows DPAPI (`System.Security.Cryptography.ProtectedData`)
- **QR Decoding:** ZXing.Net with high-density bicubic scaling fallback
- **Data Format:** Locally stored encrypted JSON database located at `%APPDATA%\Win2FA\vault.db`
- **Zero-Trust Memory Sanitization:** Secrets and decrypted seeds are immediately scrubbed and overwritten in RAM after use to prevent memory-dump attacks.

## License

This project is licensed under the MIT License.
