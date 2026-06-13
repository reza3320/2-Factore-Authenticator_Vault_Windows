using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using ZXing;
using System.IO;
using System.Drawing;
using System.Windows.Media;

namespace Win2FA
{
    public class ObservableKey
    {
        public string Id { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string AccountName { get; set; } = "";
        public string Code { get; set; } = "000000";
        public string Base32Secret { get; set; } = "";
    }

    public partial class MainWindow : Window
    {
        private List<VaultEntry> _allEntries = new List<VaultEntry>();
        private ObservableCollection<ObservableKey> _displayedKeys = new ObservableCollection<ObservableKey>();
        private DispatcherTimer _timer = new DispatcherTimer();

        private bool _isSystemThemeSubscribed = false;
        private System.Windows.Forms.NotifyIcon? _notifyIcon;
        private TrayWindow? _trayWindow;
        private string _currentThemeMode = "system";

        public MainWindow()
        {
            InitializeComponent();
            KeysItemsControl.ItemsSource = _displayedKeys;

            // Load secure DPAPI vault on start
            _allEntries = Vault.LoadEntries();
            RefreshDisplayList();

            // Set high-frequency countdown clock
            _timer.Interval = TimeSpan.FromMilliseconds(200);
            _timer.Tick += Timer_Tick;
            _timer.Start();

            // Apply system theme on boot once all elements are initialized
            ApplyTheme("system");

            // Initialize Background Tray Daemon
            InitializeNotifyIcon();
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int remainingSeconds = 30 - (int)(epoch % 30);

            SecondsRemainingText.Text = $"{remainingSeconds}s";
            TimeProgressBar.Value = remainingSeconds;

            // Trigger code refresh on rollover boundary
            if (epoch % 30 == 0 || _displayedKeys.Count > 0 && _displayedKeys[0].Code == "000000")
            {
                RefreshTotpCodes();
            }
        }

        private void RefreshDisplayList()
        {
            string query = SearchBox.Text.Trim().ToLowerInvariant();
            _displayedKeys.Clear();

            var filtered = string.IsNullOrEmpty(query)
                ? _allEntries
                : _allEntries.Where(e => e.Issuer.ToLowerInvariant().Contains(query) || e.AccountName.ToLowerInvariant().Contains(query));

            foreach (var item in filtered)
            {
                _displayedKeys.Add(new ObservableKey
                {
                    Id = item.Id,
                    Issuer = item.Issuer,
                    AccountName = item.AccountName,
                    Base32Secret = item.Base32Secret,
                    Code = "000000"
                });
            }
            RefreshTotpCodes();
            UpdateTrayIcon();
        }

        private void RefreshTotpCodes()
        {
            if (KeysItemsControl == null) return; // Prevent NullReferenceException during early XAML parsing

            foreach (var key in _displayedKeys)
            {
                try
                {
                    byte[] secretBytes = Totp.Base32Decode(key.Base32Secret);
                    key.Code = Totp.GeneratePin(secretBytes);
                }
                catch (Exception)
                {
                    key.Code = "ERROR";
                }
            }
            // Trigger UI refresh
            KeysItemsControl.Items.Refresh();
        }

        private void ThemeButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentThemeMode == "system")
            {
                _currentThemeMode = "dark";
                ThemeButton.ToolTip = "Theme: Dark (Click to change)";
            }
            else if (_currentThemeMode == "dark")
            {
                _currentThemeMode = "light";
                ThemeButton.ToolTip = "Theme: Light (Click to change)";
            }
            else
            {
                _currentThemeMode = "system";
                ThemeButton.ToolTip = "Theme: System (Click to change)";
            }
            ApplyTheme(_currentThemeMode);
        }

        private void ApplyTheme(string theme)
        {
            if (theme == "system")
            {
                if (!_isSystemThemeSubscribed)
                {
                    SystemEvents.UserPreferenceChanged += SystemEvents_UserPreferenceChanged;
                    _isSystemThemeSubscribed = true;
                }
                string systemTheme = GetWindowsSystemTheme();
                ApplyThemeColors(systemTheme);

                // System shows BOTH icons side-by-side (combined path data)
                if (ThemeIconPath != null)
                {
                    ThemeIconPath.Data = System.Windows.Media.Geometry.Parse(
                        "M6 4.5a3 3 0 110 6 3 3 0 010-6z M6 1v2 M6 11v2 M1.5 7.5h2 M9.5 7.5h2 M2.46 3.96l1.42 1.42 M9.54 3.96l-1.42 1.42 M2.46 11.04l1.42-1.42 M9.54 11.04l-1.42-1.42 M14 4a4.5 4.5 0 104.5 4.5 4.9 4.9 0 01-4.5-4.5z");
                }
            }
            else if (theme == "dark")
            {
                if (_isSystemThemeSubscribed)
                {
                    SystemEvents.UserPreferenceChanged -= SystemEvents_UserPreferenceChanged;
                    _isSystemThemeSubscribed = false;
                }
                ApplyThemeColors("dark");

                // Dark shows only Moon path data
                if (ThemeIconPath != null)
                {
                    ThemeIconPath.Data = System.Windows.Media.Geometry.Parse(
                        "M14 4a4.5 4.5 0 104.5 4.5 4.9 4.9 0 01-4.5-4.5z");
                }
            }
            else // light
            {
                if (_isSystemThemeSubscribed)
                {
                    SystemEvents.UserPreferenceChanged -= SystemEvents_UserPreferenceChanged;
                    _isSystemThemeSubscribed = false;
                }
                ApplyThemeColors("light");

                // Light shows only Sun path data
                if (ThemeIconPath != null)
                {
                    ThemeIconPath.Data = System.Windows.Media.Geometry.Parse(
                        "M6 4.5a3 3 0 110 6 3 3 0 010-6z M6 1v2 M6 11v2 M1.5 7.5h2 M9.5 7.5h2 M2.46 3.96l1.42 1.42 M9.54 3.96l-1.42 1.42 M2.46 11.04l1.42-1.42 M9.54 11.04l-1.42-1.42");
                }
            }
        }

        private void SystemEvents_UserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category == UserPreferenceCategory.General)
            {
                Dispatcher.Invoke(() => {
                    if (_currentThemeMode == "system")
                    {
                        ApplyTheme("system");
                    }
                });
            }
        }

        private string GetWindowsSystemTheme()
        {
            try
            {
                using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    if (key != null)
                    {
                        object? val = key.GetValue("AppsUseLightTheme");
                        if (val != null && (int)val == 1)
                        {
                            return "light";
                        }
                    }
                }
            }
            catch { }
            return "dark"; // Default fallback
        }

        private string GetWindowsTaskbarTheme()
        {
            try
            {
                using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    if (key != null)
                    {
                        object? val = key.GetValue("SystemUsesLightTheme");
                        if (val != null && (int)val == 1)
                        {
                            return "light";
                        }
                    }
                }
            }
            catch { }
            return "dark"; // Default fallback
        }

        private void ApplyThemeColors(string themeMode)
        {
            if (themeMode == "light")
            {
                SetResourceColor("BgBrush", "#F4F4F6");
                SetResourceColor("CardBgBrush", "#FFFFFF");
                SetResourceColor("BorderBrush", "#D1D1D6");
                SetResourceColor("AccentBrush", "#B8860B");
                SetResourceColor("AccentHoverBrush", "#8B6508");
                SetResourceColor("TextBrush", "#1C1C1E");
                SetResourceColor("MutedTextBrush", "#6E6E73");
            }
            else // dark
            {
                SetResourceColor("BgBrush", "#0B0B0F");
                SetResourceColor("CardBgBrush", "#12121A");
                SetResourceColor("BorderBrush", "#22222F");
                SetResourceColor("AccentBrush", "#DAA520");
                SetResourceColor("AccentHoverBrush", "#B8860B");
                SetResourceColor("TextBrush", "#ECECEF");
                SetResourceColor("MutedTextBrush", "#8F8F9F");
            }
            RefreshTotpCodes();
            UpdateTrayIcon();
        }

        private void SetResourceColor(string key, string hexColor)
        {
            var color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hexColor);
            var brush = new SolidColorBrush(color);
            brush.Freeze(); // Enhances WPF rendering performance
            Application.Current.Resources[key] = brush;
        }

        private void Card_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            var border = sender as Border;
            var key = border?.DataContext as ObservableKey;
            if (key != null && key.Code != "000000" && key.Code != "ERROR" && key.Code != "COPIED!")
            {
                Clipboard.SetText(key.Code);
                
                // Trigger visual "COPIED!" tactile feedback in-place of code
                string originalCode = key.Code;
                key.Code = "COPIED!";
                KeysItemsControl.Items.Refresh();
                
                var copyTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.0) };
                copyTimer.Tick += (s, ev) =>
                {
                    key.Code = originalCode;
                    KeysItemsControl.Items.Refresh();
                    copyTimer.Stop();
                };
                copyTimer.Start();
            }
        }

        private void AddSingleKey_Click(object sender, RoutedEventArgs e)
        {
            // Clear prior entry buffers
            ManualIssuerBox.Text = "";
            ManualAccountBox.Text = "";
            ManualSecretBox.Text = "";
            
            // Show modal dialog overlay
            AddAccountModal.Visibility = Visibility.Visible;
            ManualIssuerBox.Focus();
        }

        private void CancelManualAdd_Click(object sender, RoutedEventArgs e)
        {
            AddAccountModal.Visibility = Visibility.Collapsed;
        }

        private void SaveManualAdd_Click(object sender, RoutedEventArgs e)
        {
            string issuer = ManualIssuerBox.Text.Trim();
            string account = ManualAccountBox.Text.Trim();
            string secret = ManualSecretBox.Text.Trim().Replace(" ", "").ToUpperInvariant();

            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(account) || string.IsNullOrEmpty(secret))
            {
                MessageBox.Show("Please fill in all three fields to save your key.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Verify the secret key is valid Base32
            try
            {
                Totp.Base32Decode(secret);
            }
            catch
            {
                MessageBox.Show("The secret key entered is not a valid Base32 key (A-Z, 2-7).", "Invalid Secret", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Deduplicate and insert
            if (_allEntries.Any(entry => entry.Base32Secret == secret))
            {
                MessageBox.Show("This authenticator key is already present in your vault.", "Duplicate Key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _allEntries.Add(new VaultEntry
            {
                Issuer = issuer,
                AccountName = account,
                Base32Secret = secret
            });

            // Persist securely to disk via DPAPI
            Vault.SaveEntries(_allEntries);
            RefreshDisplayList();

            // Dismiss modal
            AddAccountModal.Visibility = Visibility.Collapsed;
            MessageBox.Show($"Successfully added new offline key for '{issuer}' ({account})!", "Key Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ImportQR_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "Select 2FA QR Code Screenshot / Image",
                Filter = "Image Files (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg|All Files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
                try
                {
                    string filePath = openFileDialog.FileName;
                    using (var bitmap = (Bitmap)System.Drawing.Image.FromFile(filePath))
                    {
                        var reader = new ZXing.Windows.Compatibility.BarcodeReader
                        {
                            AutoRotate = true,
                            Options = new ZXing.Common.DecodingOptions
                            {
                                TryHarder = true,
                                PossibleFormats = new List<BarcodeFormat> { BarcodeFormat.QR_CODE }
                            }
                        };
                        var result = reader.Decode(bitmap);

                        if (result == null)
                        {
                            // Fallback: Scale up by 2x using high-quality bicubic interpolation to enlarge and sharpen high-density pixels
                            using (var resized = new Bitmap(bitmap.Width * 2, bitmap.Height * 2))
                            {
                                using (var g = Graphics.FromImage(resized))
                                {
                                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                                    g.DrawImage(bitmap, 0, 0, resized.Width, resized.Height);
                                }
                                result = reader.Decode(resized);
                            }
                        }

                        if (result == null || string.IsNullOrEmpty(result.Text))
                        {
                            MessageBox.Show("Failed to read any QR code in this screenshot. Please ensure the QR code is clearly visible and not cut off.", "QR Read Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }

                        // --- BRANCH 1: Standard Single Key QR Code (otpauth://) ---
                        if (result.Text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
                        {
                            var uri = new Uri(result.Text);
                            string secret = "";
                            string issuer = "";
                            string account = "";

                            var query = uri.Query;
                            if (!string.IsNullOrEmpty(query))
                            {
                                var parts = query.TrimStart('?').Split('&');
                                foreach (var part in parts)
                                {
                                    var kv = part.Split('=');
                                    if (kv.Length == 2)
                                    {
                                        string k = kv[0].ToLowerInvariant();
                                        string v = Uri.UnescapeDataString(kv[1]);
                                        if (k == "secret") secret = v.Replace(" ", "").ToUpperInvariant();
                                        else if (k == "issuer") issuer = v.Trim();
                                    }
                                }
                            }

                            string path = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
                            if (path.Contains(":"))
                            {
                                var labelParts = path.Split(':');
                                if (string.IsNullOrEmpty(issuer)) issuer = labelParts[0].Trim();
                                account = labelParts[1].Trim();
                            }
                            else
                            {
                                account = path.Trim();
                                if (string.IsNullOrEmpty(issuer)) issuer = "Unknown";
                            }

                            if (string.IsNullOrEmpty(secret))
                            {
                                MessageBox.Show("Failed to locate any 2FA secret key inside the QR code.", "Parsing Error", MessageBoxButton.OK, MessageBoxImage.Error);
                                return;
                            }

                            // Verify valid Base32 secret
                            try { Totp.Base32Decode(secret); }
                            catch
                            {
                                MessageBox.Show("The secret key inside the QR code is not a valid Base32 string.", "Invalid Secret", MessageBoxButton.OK, MessageBoxImage.Error);
                                return;
                            }

                            if (!_allEntries.Any(entry => entry.Base32Secret == secret))
                            {
                                _allEntries.Add(new VaultEntry
                                {
                                    Issuer = issuer,
                                    AccountName = account,
                                    Base32Secret = secret
                                });
                                Vault.SaveEntries(_allEntries);
                                RefreshDisplayList();
                                MessageBox.Show($"Successfully imported key for '{issuer}' ({account}) from single QR code!", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            else
                            {
                                MessageBox.Show("This key is already present in your vault database.", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            return;
                        }

                        // --- BRANCH 2: Google Authenticator Batch Migration (otpauth-migration://) ---
                        if (result.Text.StartsWith("otpauth-migration://offline", StringComparison.OrdinalIgnoreCase))
                        {
                            var imported = GoogleAuthParser.ParseMigrationUri(result.Text);
                            if (imported.Count == 0)
                            {
                                MessageBox.Show("Successfully decoded QR code, but found 0 individual 2FA secrets.", "Import Summary", MessageBoxButton.OK, MessageBoxImage.Information);
                                return;
                            }

                            int addedCount = 0;
                            foreach (var acc in imported)
                            {
                                if (!_allEntries.Any(entry => entry.Base32Secret == acc.Secret))
                                {
                                    _allEntries.Add(new VaultEntry
                                    {
                                        Issuer = acc.Issuer,
                                        AccountName = acc.AccountName,
                                        Base32Secret = acc.Secret
                                    });
                                    addedCount++;
                                }
                            }

                            if (addedCount > 0)
                            {
                                Vault.SaveEntries(_allEntries);
                                RefreshDisplayList();
                                MessageBox.Show($"Successfully parsed and imported {addedCount} new authenticator key(s) into your encrypted DPAPI vault!", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            else
                            {
                                MessageBox.Show("All imported authenticator keys are already present in your vault database.", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                            }
                            return;
                        }

                        MessageBox.Show("The decoded QR code is not a valid Google Authenticator or standard otpauth:// payload.", "Invalid Payload", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("An unexpected error occurred during import: " + ex.Message, "System Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            RefreshDisplayList();
        }

        private void SearchBox_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkText.Visibility = Visibility.Collapsed;
        }

        private void SearchBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(SearchBox.Text))
            {
                WatermarkText.Visibility = Visibility.Visible;
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            if (_isSystemThemeSubscribed)
            {
                SystemEvents.UserPreferenceChanged -= SystemEvents_UserPreferenceChanged;
            }
            base.OnClosed(e);
        }

        private void InitializeNotifyIcon()
        {
            try
            {
                _trayWindow = new TrayWindow();

                _notifyIcon = new System.Windows.Forms.NotifyIcon();
                _notifyIcon.Text = "Win2FA - Secure Offline Authenticator";
                
                // Set minimalist tray icon dynamically based on system theme
                UpdateTrayIcon();

                _notifyIcon.Visible = true;
                _notifyIcon.MouseClick += (object? s, System.Windows.Forms.MouseEventArgs e) =>
                {
                    if (e.Button == System.Windows.Forms.MouseButtons.Left)
                    {
                        if (_trayWindow != null)
                        {
                            _trayWindow.PopulateAndShow(_allEntries);
                        }
                    }
                };

                // Hook Quit Context Menu
                var contextMenu = new System.Windows.Forms.ContextMenuStrip();
                var openItem = new System.Windows.Forms.ToolStripMenuItem("Show Main Window", null, (s, e) => { this.Show(); this.Activate(); });
                
                var startupItem = new System.Windows.Forms.ToolStripMenuItem("Start at Startup", null, (s, ev) => {
                    // State automatically toggled by CheckOnClick
                });
                startupItem.CheckOnClick = true;
                startupItem.Checked = IsStartupEnabled();
                startupItem.CheckedChanged += (s, ev) => {
                    SetStartup(startupItem.Checked);
                };

                var quitItem = new System.Windows.Forms.ToolStripMenuItem("Exit Secure Vault", null, (s, e) => {
                    if (_notifyIcon != null)
                    {
                        _notifyIcon.Visible = false;
                        _notifyIcon.Dispose();
                    }
                    Application.Current.Shutdown();
                });
                contextMenu.Items.Add(openItem);
                contextMenu.Items.Add(startupItem);
                contextMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
                contextMenu.Items.Add(quitItem);
                _notifyIcon.ContextMenuStrip = contextMenu;

                // Hook close event to minimize instead of shut down
                this.Closing += MainWindow_Closing;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("NotifyIcon initialization failed: " + ex.Message);
                MessageBox.Show("Background service failed to start, but the main app is running: " + ex.Message, "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void UpdateTrayIcon()
        {
            if (_notifyIcon == null) return;
            try
            {
                string theme = _currentThemeMode == "system" ? GetWindowsTaskbarTheme() : _currentThemeMode;
                string iconFile = theme == "light" ? "tray_dark.ico" : "tray_light.ico";
                
                // Load embedded icon from WPF assembly resources
                var resourceUri = new Uri($"pack://application:,,,/{iconFile}", UriKind.Absolute);
                var streamInfo = System.Windows.Application.GetResourceStream(resourceUri);
                if (streamInfo != null)
                {
                    using (var stream = streamInfo.Stream)
                    {
                        _notifyIcon.Icon = new System.Drawing.Icon(stream);
                    }
                }
                else
                {
                    // Fallback to app icon from assembly resources
                    var appResourceUri = new Uri("pack://application:,,,/icon.ico", UriKind.Absolute);
                    var appStreamInfo = System.Windows.Application.GetResourceStream(appResourceUri);
                    if (appStreamInfo != null)
                    {
                        using (var stream = appStreamInfo.Stream)
                        {
                            _notifyIcon.Icon = new System.Drawing.Icon(stream);
                        }
                    }
                    else
                    {
                        // Fallback to system icon
                        _notifyIcon.Icon = System.Drawing.SystemIcons.Application;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Failed to update tray icon: " + ex.Message);
                if (_notifyIcon.Icon == null)
                {
                    try
                    {
                        _notifyIcon.Icon = System.Drawing.SystemIcons.Application;
                    }
                    catch { }
                }
            }
        }

        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            e.Cancel = true;
            this.Hide();
            
            if (_notifyIcon != null)
            {
                _notifyIcon.ShowBalloonTip(
                    2000,
                    "Win2FA Running Offline",
                    "Click the tray key icon at any time to instantly view and copy your codes.",
                    System.Windows.Forms.ToolTipIcon.Info
                );
            }
        }

        private bool IsStartupEnabled()
        {
            try
            {
                using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    if (key != null)
                    {
                        return key.GetValue("Win2FA") != null;
                    }
                }
            }
            catch { }
            return false;
        }

        private void SetStartup(bool enable)
        {
            try
            {
                using (RegistryKey? key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null)
                    {
                        if (enable)
                        {
                            if (Environment.ProcessPath != null)
                            {
                                key.SetValue("Win2FA", $"\"{Environment.ProcessPath}\"");
                            }
                        }
                        else
                        {
                            key.DeleteValue("Win2FA", false);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to save startup configuration: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
