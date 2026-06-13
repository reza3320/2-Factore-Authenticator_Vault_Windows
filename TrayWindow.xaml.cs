using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Win2FA
{
    public partial class TrayWindow : Window
    {
        private List<VaultEntry> _allEntries = new List<VaultEntry>();
        private ObservableCollection<ObservableKey> _displayedKeys = new ObservableCollection<ObservableKey>();
        private DispatcherTimer _timer = new DispatcherTimer();

        public TrayWindow()
        {
            InitializeComponent();
            TrayKeysItemsControl.ItemsSource = _displayedKeys;

            _timer.Interval = TimeSpan.FromMilliseconds(200);
            _timer.Tick += Timer_Tick;
            _timer.Start();
        }

        public void PopulateAndShow(List<VaultEntry> entries)
        {
            _allEntries = entries;
            RefreshDisplayList();

            // Position near the system tray clock automatically
            PositionWindowNearTray();

            this.Show();
            this.Activate();
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            long epoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int remainingSeconds = 30 - (int)(epoch % 30);

            SecondsText.Text = $"{remainingSeconds}s";
            TrayProgressBar.Value = remainingSeconds;

            if (epoch % 30 == 0 || _displayedKeys.Count > 0 && _displayedKeys[0].Code == "000000")
            {
                RefreshTotpCodes();
            }
        }

        private void RefreshDisplayList()
        {
            _displayedKeys.Clear();
            foreach (var item in _allEntries)
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
        }

        private void RefreshTotpCodes()
        {
            if (TrayKeysItemsControl == null) return;
            foreach (var key in _displayedKeys)
            {
                try
                {
                    byte[] secretBytes = Totp.Base32Decode(key.Base32Secret);
                    key.Code = Totp.GeneratePin(secretBytes);
                }
                catch
                {
                    key.Code = "ERROR";
                }
            }
            TrayKeysItemsControl.Items.Refresh();
        }

        private void TrayCard_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            var border = sender as Border;
            var key = border?.DataContext as ObservableKey;
            if (key != null && key.Code != "000000" && key.Code != "ERROR" && key.Code != "COPIED!")
            {
                Clipboard.SetText(key.Code);
                string originalCode = key.Code;
                key.Code = "COPIED!";
                TrayKeysItemsControl.Items.Refresh();

                var copyTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.0) };
                copyTimer.Tick += (s, ev) =>
                {
                    key.Code = originalCode;
                    TrayKeysItemsControl.Items.Refresh();
                    copyTimer.Stop();
                };
                copyTimer.Start();
            }
        }

        private void PositionWindowNearTray()
        {
            var workingArea = SystemParameters.WorkArea;
            this.Left = workingArea.Right - this.Width - 10;
            this.Top = workingArea.Bottom - this.Height - 10;
        }

        public DateTime LastHiddenTime { get; private set; } = DateTime.MinValue;

        private void Window_Deactivated(object sender, EventArgs e)
        {
            this.Hide();
            LastHiddenTime = DateTime.UtcNow;
        }
    }
}
