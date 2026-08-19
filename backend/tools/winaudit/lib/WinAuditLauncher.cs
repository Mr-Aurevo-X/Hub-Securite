using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class Program {
    [STAThread]
    static void Main() {
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
            string script = Path.Combine(root, "WinAudit.ps1");
            if (!File.Exists(script)) {
                MessageBox.Show("WinAudit.ps1 introuvable a cote de WinAudit.exe.\nDossier: " + root, "WinAudit Pro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            var psi = new ProcessStartInfo {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + script + "\"",
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = root
            };
            Process.Start(psi);
        }
        catch (Exception ex) {
            MessageBox.Show(ex.Message, "WinAudit Pro", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
