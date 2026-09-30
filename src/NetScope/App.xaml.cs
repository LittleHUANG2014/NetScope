using System;
using System.Text;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace NetScope;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // 注册 GB18030 等代码页编码，供 netsh 输出解码使用
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        if (!Services.NpcapManager.IsAdmin)
        {
            MessageBox.Show("Administrator privileges are required for Npcap capture, raw frame sending, and address changes.\nRight-click and run as administrator.",
                "NetScope", MessageBoxButton.OK, MessageBoxImage.Warning);
            Shutdown(1);
        }
    }
}
