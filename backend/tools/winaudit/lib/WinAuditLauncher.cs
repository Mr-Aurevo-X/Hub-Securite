using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class Program {
    const string ScriptName = "WinAudit.ps1";

    [STAThread]
    static void Main() {
        try {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\', '/');
            string script = Path.Combine(root, ScriptName);
            if (!File.Exists(script)) {
                ShowError("Script introuvable.");
                return;
            }
            if (!VerifyOptionalHash(script)) {
                ShowError("Integrite du script invalide.");
                return;
            }
            var psi = new ProcessStartInfo {
                FileName = ResolvePowerShell(),
                Arguments = "-NoProfile -ExecutionPolicy RemoteSigned -File \"" + script + "\"",
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = root
            };
            Process.Start(psi);
        }
        catch (Exception) {
            ShowError("Impossible de lancer WinAudit.");
        }
    }

    static void ShowError(string message) {
        MessageBox.Show(message, "WinAudit Pro", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    static string ResolvePowerShell() {
        string ps = Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        return File.Exists(ps) ? ps : "powershell.exe";
    }

    static bool VerifyOptionalHash(string scriptPath) {
        string sidecar = scriptPath + ".sha256";
        if (!File.Exists(sidecar)) {
            return true;
        }
        string expected = File.ReadAllText(sidecar, Encoding.UTF8).Trim().ToLowerInvariant();
        if (expected.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) {
            expected = expected.Substring(7).Trim();
        }
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(scriptPath)) {
            string actual = string.Concat(sha.ComputeHash(stream).Select(b => b.ToString("x2")));
            return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
