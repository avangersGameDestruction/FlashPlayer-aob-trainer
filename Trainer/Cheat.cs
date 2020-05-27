using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

public class Cheat
{
    public string Name = "";
    public string ScanCode = "";
    public string ChangeToCode = "";
    public string DisabledCode = "";
    public IntPtr[] Addresses = { IntPtr.Zero };
    public bool Found = false;
    public bool FastScan = true;
    public int AddressAlign = -1;
    public void ScanCheat(Process Proc)
    {
        try
        {
            AobScan Scan = new AobScan();
            if (FastScan == true && AddressAlign != -1)
            {
                Scan.FastScan = true;
                Scan.AddAlign = AddressAlign % 8;
            }
            Addresses = Scan.ScanArray(Proc, ScanCode);
            if (Addresses != null)
            {
                if (Addresses.Length > 0)
                {
                    if (Addresses[0] == IntPtr.Zero)
                    {
                        Array.Clear(Addresses, 0, Addresses.Length);
                        Found = false;
                    }
                    else
                    {
                        Found = true;
                    }
                }
                else
                {
                    Array.Clear(Addresses, 0, Addresses.Length);
                    Found = false;
                }
            }
            else
            {
                Found = false;
            }
        }
        catch (Exception ex)
        {
            System.Windows.Forms.MessageBox.Show(ex.ToString());
        }
    }
    public void ActivateCheat(Process Proc)
    {
        try
        {
            AobScan Scan = new AobScan();
            foreach (IntPtr add in Addresses)
            {
                Scan.WriteArray(Proc, add, ChangeToCode);
            }
        }
        catch (Exception ex)
        {
            System.Windows.Forms.MessageBox.Show(ex.ToString());
        }
    }
    public void DeactivateCheat(Process Proc)
    {
        try
        {
            foreach (IntPtr add in Addresses)
            {
                AobScan Scan = new AobScan();
                if (DisabledCode == "")
                {
                    DisabledCode = ScanCode;
                }
                Scan.WriteArray(Proc, add, DisabledCode);
            }
        }
        catch (Exception ex)
        {
            System.Windows.Forms.MessageBox.Show(ex.ToString());
        }
    }
}