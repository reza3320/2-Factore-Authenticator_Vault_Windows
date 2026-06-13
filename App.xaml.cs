using System.Windows;

namespace Win2FA
{
    public partial class App : System.Windows.Application
    {
        private void Application_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show($"An unhandled exception occurred:\n\n{e.Exception.Message}\n\nStack Trace:\n{e.Exception.StackTrace}", "Critical Error", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
