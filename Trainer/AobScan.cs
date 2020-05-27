using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;

using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Windows.Forms;

public class AobScan
{
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    [DllImport("kernel32.dll")]
    protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesRead);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)]
    protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    // Estrutura para x86
    [StructLayout(LayoutKind.Sequential)]
    protected struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public uint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    List<MEMORY_BASIC_INFORMATION> MappedMemory { get; set; }
    private enum AllocationProtectEnum : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }
    //Memory State
    //https://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
    private enum StateEnum : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }
    private enum TypeEnum : uint
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }
    public static string GetSystemMessage(uint errorCode)
    {
        var exception = new System.ComponentModel.Win32Exception((int)errorCode);
        return exception.Message;
    }
    //######################## VARS #############################
    public UInt64 BeginScan = 0x0;
    public UInt64 EndScan = 0xFFFFFFFF;//limite de x86
    Boolean StopTheFirst = false;
    Process Attacked;
    List<IntPtr> AddressList = new List<IntPtr>();
    //###########################################################
    protected void MemInfo(IntPtr pHandle)
    {
        IntPtr mAddress;
        mAddress = (IntPtr)BeginScan;
        while (true)
        {
            if ((ulong)mAddress > EndScan) break;
            MEMORY_BASIC_INFORMATION MBI = new MEMORY_BASIC_INFORMATION();
            int MemDump = VirtualQueryEx(pHandle, mAddress, out MBI, (uint)Marshal.SizeOf(MBI));
            if (MemDump == 0) break;
            if ((MBI.State & (uint)StateEnum.MEM_COMMIT) != 0 && // Páginas que contêm a memória do armazenamento físico 
                !((MBI.Protect & (uint)AllocationProtectEnum.PAGE_GUARD)
                == (uint)AllocationProtectEnum.PAGE_GUARD)) // Evita páginas de guarda
            {
                MappedMemory.Add(MBI); // Lista de mapeamento da memoria
            }
            mAddress = (IntPtr)((int)MBI.BaseAddress + (int)MBI.RegionSize);
        }
    }
    byte[] SigScan;
    bool[] SigScanUnknown;
    public int AddAlign = -1;
    // Normal ScanInBuff
    protected IntPtr ScanInBuff(IntPtr Address, byte[] Buff)
    {
        Int64 TamanhoBuf = Buff.Length;
        int TamanhoScan = SigScan.Length;
        int TScan = TamanhoScan - 1;
        Int64 go = 0;
        while (go <= (TamanhoBuf - TamanhoScan - 1))
        {
            if (Buff[go] == SigScan[0]) // Confere se o primeiro byte do array é igual o do ponto atual do buffer  
            {
                for (int i = TScan; ((SigScanUnknown[i])/* Ou a máscara nesses byte é indefinida ou*/ ||
                    (Buff[go + i] == SigScan[i]))/* Ou os bytes são iguais*/; i--/*Vai reduzindo o valor do tamanho do array*/)
                    if (i == 0) // Chegou a zero, achou o array
                    {
                        if (StopTheFirst) // Parar ao encontrar o primeiro ? 
                            return new IntPtr(go);
                        else
                        {
                            if ((UInt64)(Address.ToInt64() + go) >= BeginScan &&
                                (UInt64)(Address.ToInt64() + go) <= EndScan)
                                AddressList.Add((IntPtr)(Address.ToInt64() + go)); // Adiciona à lista com os endereços encontrados
                        }
                        break;
                    }
            }
            go += 1;
        }
        return IntPtr.Zero;
    }
    // ScanInBuff Alinhado
    protected IntPtr ScanInBuffFast(IntPtr Address, byte[] Buff)
    {
        Int64 TamanhoBuf = Buff.Length;
        int TamanhoScan = SigScan.Length;
        int TScan = TamanhoScan - 1;
        Int64 go = (AddAlign % 8 - Address.ToInt64() % 8 + 16) % 8;

        while (go <= (TamanhoBuf - TamanhoScan - 1))
        {
            if (Buff[go] == SigScan[0]) // Confere se o primeiro byte do array é igual o do ponto atual do buffer  
            {
                for (int i = TScan; ((SigScanUnknown[i])/* Ou a máscara nesses byte é indefinida ou*/ ||
                    (Buff[go + i] == SigScan[i]))/* Ou os bytes são iguais*/; i--/*Vai reduzindo o valor do tamanho do array*/)
                    if (i == 0) // Chegou a zero, achou o array
                    {
                        if (StopTheFirst) // Parar ao encontrar o primeiro ? 
                            return new IntPtr(go);
                        else
                        {
                            if ((UInt64)(Address.ToInt64() + go) >= BeginScan &&
                                (UInt64)(Address.ToInt64() + go) <= EndScan)
                                AddressList.Add((IntPtr)(Address.ToInt64() + go)); // Adiciona a lista com os endereços encontrados
                        }
                        break;
                    }
            }
            go += 8;
        }
        return IntPtr.Zero;
    }
    IntPtr[] toReturn = null;
    string ArrayString;
    public bool FastScan = false;
    IntPtr hProcess = IntPtr.Zero;
    public IntPtr[] ScanArray(Process P, string ArrayString_)
    {
        if (P == null) // Se não encontrar o processo
        {
            return toReturn;
        }
        else
        {
            Attacked = Process.GetProcessById(P.Id); // ReCheck Pos Privileges
            hProcess = Attacked.Handle;
        }
        ArrayString = ArrayString_;
        if (FastScan)
        {
            StartFastScan();
        }
        else
        {
            StartScan();
        }
        return toReturn;
    }
    void StartScan()
    {
        String[] BytesToScan = ArrayString.Split(" "[0]);
        for (int i = 0; i < BytesToScan.Length; i++)
        {
            if (BytesToScan[i] == "?") // Caso informou apenas um interrogação 
            {
                BytesToScan[i] = "??";
            }
        }
        int TamanhoScan = BytesToScan.Length;
        SigScan = new byte[TamanhoScan];
        SigScanUnknown = new bool[TamanhoScan];
        for (int i = 0; i < TamanhoScan; i++)
        {
            if (BytesToScan[i] == "??") // Bytes indefinidos altera pra zero
            {
                SigScan[i] = 0x0;
                SigScanUnknown[i] = true;
            }
            else
            {
                SigScanUnknown[i] = false;
                SigScan[i] = Convert.ToByte(BytesToScan[i], 16); // Converte byte a byte da máscara
            }
        }
        MappedMemory = new List<MEMORY_BASIC_INFORMATION>(); // Cria uma lista pra salvar o mapa da memória
        MemInfo(hProcess); // Faz o mapeamento
        for (int i = 0; i < MappedMemory.Count; i++) // Procurar em cada região
        {
            byte[] buff = new byte[MappedMemory[i].RegionSize]; // Define o tamanho do buffer com o tamanho da região
            ReadProcessMemory(hProcess, (IntPtr)MappedMemory[i].BaseAddress, buff, (uint)MappedMemory[i].RegionSize, 0);
            IntPtr Result = IntPtr.Zero;
            if (buff.Length > 0)
            {
                Result = ScanInBuff((IntPtr)MappedMemory[i].BaseAddress, buff);
            }
            if (StopTheFirst)
            {
                if (Result != IntPtr.Zero)
                {
                    toReturn = new IntPtr[0];
                    toReturn[0] = (IntPtr)((int)MappedMemory[i].BaseAddress + Convert.ToInt64(Result));
                    return;
                }
            }
        }
        if (!StopTheFirst && AddressList.Count > 0)
        {
            toReturn = new IntPtr[AddressList.Count];
            for (int l = 0; l < (AddressList.Count); l++)
            {
                toReturn[l] = AddressList[l];
            }
            AddressList.Clear();
            return;
        }
        return;
    }
    void StartFastScan()
    {
        String[] BytesToScan = ArrayString.Split(" "[0]);
        for (int i = 0; i < BytesToScan.Length; i++)
        {
            if (BytesToScan[i] == "?") // Caso informou apenas uma interrogação 
            {
                BytesToScan[i] = "??";
            }
        }
        int TamanhoScan = BytesToScan.Length;
        SigScan = new byte[TamanhoScan];
        SigScanUnknown = new bool[TamanhoScan];
        for (int i = 0; i < TamanhoScan; i++)
        {
            if (BytesToScan[i] == "??") // Bytes indefinidos altera para zero
            {
                SigScan[i] = 0x0;
                SigScanUnknown[i] = true;
            }
            else
            {
                SigScanUnknown[i] = false;
                SigScan[i] = Convert.ToByte(BytesToScan[i], 16); // Converte byte a byte da máscara 
            }
        }
        MappedMemory = new List<MEMORY_BASIC_INFORMATION>(); // Cria uma lista pra salvar o mapa da memória
        MemInfo(hProcess); // Faz o mapeamento
        for (int i = 0; i < MappedMemory.Count; i++) // Procurar em cada região
        {
            byte[] buff = new byte[MappedMemory[i].RegionSize]; // Define o tamanho do buffer com o tamanho da região
            ReadProcessMemory(hProcess, (IntPtr)MappedMemory[i].BaseAddress, buff, (uint)MappedMemory[i].RegionSize, 0);
            IntPtr Result = IntPtr.Zero;
            if (buff.Length > 0)
            {
                Result = ScanInBuffFast((IntPtr)MappedMemory[i].BaseAddress, buff);
            }
            if (StopTheFirst)
            {
                if (Result != IntPtr.Zero)
                {
                    toReturn = new IntPtr[0];
                    toReturn[0] = (IntPtr)((int)MappedMemory[i].BaseAddress + Convert.ToInt64(Result));
                    return;
                }
            }
        }
        if (!StopTheFirst && AddressList.Count > 0)
        {
            toReturn = new IntPtr[AddressList.Count];
            for (int l = 0; l < (AddressList.Count); l++)
            {
                toReturn[l] = AddressList[l];
            }
            AddressList.Clear();
            return;
        }
        return;
    }
    public bool WriteArray(Process proc, IntPtr address, string ArrayString)
    {
        if (proc == null)
        {
            return false;
        }
        String[] BytesToScan = ArrayString.Split(" "[0]);
        for (int i = 0; i < BytesToScan.Length; i++)
        {
            if (BytesToScan[i] == "?" || BytesToScan[i] == "??")
            {
                // Não mudar esse byte
            }
            else
            {
                byte this_byte = Convert.ToByte(BytesToScan[i], 0x10);
                WriteProcessMemory(proc.Handle, new IntPtr(address.ToInt32() + i), new byte[] { this_byte }, 1, 0);
            }
        }
        return true;
    }
}