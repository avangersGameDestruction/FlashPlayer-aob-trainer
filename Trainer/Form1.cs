using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;

namespace Trainer
{
    public partial class Form1 : Form
    {
        int ProcessID = 0;
        Process kogProc;
        // Cheats
        Cheat CheatName = new Cheat();

        public Form1()
        {
            InitializeComponent();
        }

        private void LoadAllCheats()
        {
            // CheatName
            CheatName.ScanCode = "put aob1 here";
            CheatName.ChangeToCode = "put aob2 here";
            CheatName.AddressAlign = 0x0215;
            // Others...
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            LoadAllCheats();
        }

        private void Timer1_Tick(object sender, EventArgs e)
        {
            Process[] kogProcs = Process.GetProcessesByName("processName");
            if (kogProcs.Length == 0)
            {
                if (ProcessID != 0)
                {
                    // Reset Cheats - when the game is offline
                }
                ProcessID = 0;
            }
            else
            {
                kogProc = kogProcs[0];
                if (ProcessID != kogProc.Id)
                {
                    ProcessID = kogProc.Id;
                }
                ProcessID = kogProc.Id;

            }
        }

        private void CheckBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked)
            {
                CheatName.ScanCheat(kogProc);
                if (CheatName.Found)
                {
                    CheatName.ActivateCheat(kogProc);
                }
                else
                {
                    checkBox1.CheckState = CheckState.Unchecked;
                }
            }
            else
            {
                if (CheatName.Found)
                {
                    CheatName.DeactivateCheat(kogProc);
                }
            }
        }
    }
}
