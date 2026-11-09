using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace RobRunFix
{
    static class Native
    {
        [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr requestedGuid);
        [DllImport("wintun.dll")]
        public static extern void WintunCloseAdapter(IntPtr adapter);
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);
        [DllImport("wintun.dll")]
        public static extern void WintunEndSession(IntPtr session);
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint size);
        [DllImport("wintun.dll")]
        public static extern void WintunSendPacket(IntPtr session, IntPtr packet);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetStdHandle(int handle);
        [DllImport("kernel32.dll")]
        public static extern bool GetConsoleMode(IntPtr handle, out uint mode);
        [DllImport("kernel32.dll")]
        public static extern bool SetConsoleMode(IntPtr handle, uint mode);
    }

    static class Packets
    {
        static readonly uint[] CrcTable = MakeCrcTable();
        static readonly byte[] ConnectCommand = { 0x82, 0xFF, 0x00, 0x01, 0x00, 0x00 };
        static readonly byte[] KnownSessions = { 0, 1, 2, 3, 255 };

        static uint[] MakeCrcTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                table[i] = c;
            }
            return table;
        }

        public static uint Crc32(byte[] data)
        {
            uint crc = 0xFFFFFFFFu;
            foreach (byte b in data) crc = CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        static uint ConnectCrc(byte[] packet)
        {
            byte[] copy = (byte[])packet.Clone();
            copy[4] = copy[5] = copy[6] = copy[7] = 0;
            return Crc32(copy);
        }

        public static bool IsConnect(byte[] p)
        {
            if (p.Length != 53 || p[0] != 0x8F || p[1] != 0xFF || p[24] != 2) return false;
            for (int i = 0; i < ConnectCommand.Length; i++) if (p[8 + i] != ConnectCommand[i]) return false;
            for (int i = 49; i < 53; i++) if (p[i] != 0) return false;
            if (Array.IndexOf(KnownSessions, p[14]) < 0 || Array.IndexOf(KnownSessions, p[15]) < 0) return false;
            uint stored = (uint)(p[4] << 24 | p[5] << 16 | p[6] << 8 | p[7]);
            return stored == ConnectCrc(p);
        }

        public static byte[] WithFreshSession(byte[] packet)
        {
            if (!IsConnect(packet) || (packet[14] == 0xFF && packet[15] == 0xFF)) return null;
            byte[] edited = (byte[])packet.Clone();
            edited[14] = edited[15] = 0xFF;
            uint crc = ConnectCrc(edited);
            edited[4] = (byte)(crc >> 24);
            edited[5] = (byte)(crc >> 16);
            edited[6] = (byte)(crc >> 8);
            edited[7] = (byte)crc;
            return edited;
        }

        static uint Sum(byte[] data, int offset, int length, uint sum)
        {
            for (int i = 0; i + 1 < length; i += 2) sum += (uint)(data[offset + i] << 8 | data[offset + i + 1]);
            if ((length & 1) != 0) sum += (uint)(data[offset + length - 1] << 8);
            return sum;
        }

        static ushort Fold(uint sum)
        {
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        public static byte[] BuildUdp(byte[] source, byte[] destination, int sourcePort, int destinationPort, byte[] payload, int length)
        {
            int udpLength = 8 + length;
            byte[] p = new byte[20 + udpLength];
            p[0] = 0x45;
            p[2] = (byte)(p.Length >> 8);
            p[3] = (byte)p.Length;
            p[6] = 0x40;
            p[8] = 64;
            p[9] = 17;
            Array.Copy(source, 0, p, 12, 4);
            Array.Copy(destination, 0, p, 16, 4);
            ushort ipSum = Fold(Sum(p, 0, 20, 0));
            p[10] = (byte)(ipSum >> 8);
            p[11] = (byte)ipSum;
            p[20] = (byte)(sourcePort >> 8);
            p[21] = (byte)sourcePort;
            p[22] = (byte)(destinationPort >> 8);
            p[23] = (byte)destinationPort;
            p[24] = (byte)(udpLength >> 8);
            p[25] = (byte)udpLength;
            Array.Copy(payload, 0, p, 28, length);
            ushort udpSum = Fold(Sum(p, 20, udpLength, Sum(p, 12, 8, 17u + (uint)udpLength)));
            if (udpSum == 0) udpSum = 0xFFFF;
            p[26] = (byte)(udpSum >> 8);
            p[27] = (byte)udpSum;
            return p;
        }

        public static bool IsPublic(string text)
        {
            IPAddress address;
            if (!IPAddress.TryParse(text, out address) || address.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = address.GetAddressBytes();
            if (b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
            return true;
        }
    }

    enum LogEvent { None, Connected, Dropped, BattleLeft }

    class JoinWatcher
    {
        public const int StallSeconds = 2;
        static readonly Regex Step = new Regex("NetworkStep - Changed on \"(\\w+)\"");
        static readonly Regex Address = new Regex(@"GetAddress completed id=battle host=([^.\s]+)\S* .*?addresses=([\d., ]+)");
        static readonly Regex Started = new Regex(@"PeerConnect started id=battle address=([\d.]+):\d+");
        static readonly Regex Complete = new Regex(@"PeerConnect complete id=battle address=([\d.]+):\d+");

        public string Host = "";
        public List<string> Addresses = new List<string>();
        public string PendingIp;
        public DateTime PendingSince;
        public bool PendingHandled;
        public string ConnectedIp;

        public LogEvent Feed(string line, DateTime now)
        {
            Match m = Step.Match(line);
            if (m.Success)
            {
                if (m.Groups[1].Value != "InRealmNotInBattle") return LogEvent.None;
                PendingIp = null;
                return LogEvent.BattleLeft;
            }
            if (line.Contains("RoomConnection.DisconnectedNetworkPeerPacket battle")) return LogEvent.Dropped;
            if (line.IndexOf("id=battle", StringComparison.Ordinal) < 0) return LogEvent.None;
            m = Address.Match(line);
            if (m.Success)
            {
                Host = m.Groups[1].Value;
                Addresses = m.Groups[2].Value.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                return LogEvent.None;
            }
            m = Started.Match(line);
            if (m.Success)
            {
                PendingIp = m.Groups[1].Value;
                PendingSince = now;
                PendingHandled = false;
                return LogEvent.None;
            }
            m = Complete.Match(line);
            if (m.Success)
            {
                PendingIp = null;
                ConnectedIp = m.Groups[1].Value;
                return LogEvent.Connected;
            }
            if (line.Contains("PeerConnect failed id=battle")) PendingIp = null;
            return LogEvent.None;
        }

        public bool StallDue(DateTime now)
        {
            return PendingIp != null && !PendingHandled && (now - PendingSince).TotalSeconds >= StallSeconds;
        }
    }

    class LogTail
    {
        readonly string path;
        long position;
        string partial = "";

        public LogTail(string path)
        {
            this.path = path;
            position = File.Exists(path) ? new FileInfo(path).Length : 0;
        }

        public List<string> ReadNew()
        {
            List<string> lines = new List<string>();
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (stream.Length < position)
                    {
                        position = 0;
                        partial = "";
                    }
                    if (stream.Length == position) return lines;
                    stream.Position = position;
                    byte[] buffer = new byte[Math.Min(1 << 20, stream.Length - position)];
                    int read = stream.Read(buffer, 0, buffer.Length);
                    position += read;
                    string[] parts = (partial + Encoding.GetEncoding(28591).GetString(buffer, 0, read)).Split('\n');
                    partial = parts[parts.Length - 1];
                    for (int i = 0; i < parts.Length - 1; i++) lines.Add(parts[i].TrimEnd('\r'));
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return lines;
        }
    }

    sealed class Tunnel : IDisposable
    {
        public const string Name = "RobRunFix";
        public static readonly IPAddress Address = IPAddress.Parse("198.18.99.1");
        const uint RingCapacity = 0x400000;
        readonly object sendLock = new object();
        IntPtr adapter;
        IntPtr session;

        public Tunnel()
        {
            if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == Name))
                throw new InvalidOperationException("A " + Name + " adapter already exists. Close the other copy, or restart Windows.");
            adapter = Native.WintunCreateAdapter(Name, Name, IntPtr.Zero);
            if (adapter == IntPtr.Zero) throw new InvalidOperationException("Could not create the virtual adapter: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
            session = Native.WintunStartSession(adapter, RingCapacity);
            if (session == IntPtr.Zero)
            {
                string reason = new Win32Exception(Marshal.GetLastWin32Error()).Message;
                Dispose();
                throw new InvalidOperationException("Could not start the adapter session: " + reason);
            }
            try { Configure(); }
            catch { Dispose(); throw; }
        }

        static void Configure()
        {
            string output = "";
            bool found = false;
            for (int i = 0; i < 40 && !found; i++)
            {
                found = Program.Netsh("interface ipv4 set interface interface=" + Name + " dadtransmits=0 routerdiscovery=disabled weakhostreceive=enabled store=active", out output) == 0;
                if (!found) Thread.Sleep(250);
            }
            if (!found) throw new InvalidOperationException("The virtual adapter did not appear: " + output.Trim());
            if (Program.Netsh("interface ipv4 set address name=" + Name + " source=static address=" + Address + " mask=255.255.255.255 gateway=none", out output) != 0)
                throw new InvalidOperationException("Could not set the adapter address: " + output.Trim());
            for (int i = 0; i < 40; i++)
            {
                if (AddressReady()) return;
                Thread.Sleep(250);
            }
            throw new InvalidOperationException("The adapter address never became ready.");
        }

        static bool AddressReady()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.Name != Name) continue;
                foreach (UnicastIPAddressInformation info in nic.GetIPProperties().UnicastAddresses)
                    if (info.Address.Equals(Address) && info.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Preferred) return true;
            }
            return false;
        }

        public void Send(byte[] packet)
        {
            lock (sendLock)
            {
                if (session == IntPtr.Zero) return;
                IntPtr target = Native.WintunAllocateSendPacket(session, (uint)packet.Length);
                if (target == IntPtr.Zero) return;
                Marshal.Copy(packet, 0, target, packet.Length);
                Native.WintunSendPacket(session, target);
            }
        }

        public void Dispose()
        {
            lock (sendLock)
            {
                if (session != IntPtr.Zero) Native.WintunEndSession(session);
                session = IntPtr.Zero;
                if (adapter != IntPtr.Zero) Native.WintunCloseAdapter(adapter);
                adapter = IntPtr.Zero;
            }
        }
    }

    sealed class Flow
    {
        public int ClientPort;
        public int LocalPort;
        public byte[] ClientIp;
        public IPEndPoint Server;
        public Socket Socket;
        public DateTime Created;
        public int Unchanged;
        public int Edits;
        public int LastId = -1;
        public byte[] LastPayload;
        public DateTime LastSeen;
        public volatile bool Replied;
        public volatile bool Closed;
    }

    sealed class Relay
    {
        const int MaxFlows = 16;
        const int PortsPerHour = 60;
        const int SioUdpConnReset = -1744830452;
        readonly Tunnel tunnel;
        readonly object sync = new object();
        readonly HashSet<string> watched = new HashSet<string>();
        readonly Dictionary<string, Flow> flows = new Dictionary<string, Flow>();
        readonly Queue<DateTime> opened = new Queue<DateTime>();
        readonly ConcurrentDictionary<int, bool> answeredPorts = new ConcurrentDictionary<int, bool>();
        readonly HashSet<int> relayPorts = new HashSet<int>();
        IPAddress local;
        Socket sniffer;
        public int Copied, Duplicates, Sent, SendErrors, Answers;
        public SocketError LastSendError;

        public Relay(Tunnel tunnel)
        {
            this.tunnel = tunnel;
        }

        public bool Active { get { lock (sync) return watched.Count > 0; } }

        public bool IsWatched(string ip) { lock (sync) return ip != null && watched.Contains(ip); }

        public bool HasFlows(IList<string> ips) { lock (sync) return flows.Values.Any(f => ips.Contains(f.Server.Address.ToString())); }

        public bool AnsweredBy(string ip) { lock (sync) return flows.Values.Any(f => f.Replied && f.Server.Address.ToString() == ip); }

        public bool Answered(int clientPort) { return answeredPorts.ContainsKey(clientPort); }

        public void Activate(IList<string> ips)
        {
            lock (sync)
            {
                if (sniffer == null) StartSniffer(IPAddress.Parse(ips[0]));
                foreach (string ip in ips) watched.Add(ip);
            }
        }

        public bool Rotate(IList<string> ips)
        {
            lock (sync)
            {
                while (opened.Count > 0 && (DateTime.UtcNow - opened.Peek()).TotalHours >= 1) opened.Dequeue();
                if (opened.Count >= PortsPerHour) return false;
                foreach (string key in flows.Where(f => ips.Contains(f.Value.Server.Address.ToString())).Select(f => f.Key).ToList()) Close(key);
                return true;
            }
        }

        public void DeactivateAll()
        {
            lock (sync)
            {
                watched.Clear();
                foreach (string key in flows.Keys.ToList()) Close(key);
                if (sniffer != null) sniffer.Close();
                sniffer = null;
            }
        }

        void StartSniffer(IPAddress server)
        {
            using (Socket probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                probe.Connect(server, 9);
                local = ((IPEndPoint)probe.LocalEndPoint).Address;
            }
            if (local.Equals(Tunnel.Address)) throw new InvalidOperationException("Could not find your normal network connection.");
            Socket raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            try
            {
                raw.ReceiveBufferSize = 1 << 20;
                raw.Bind(new IPEndPoint(local, 0));
                raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                raw.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
            }
            catch
            {
                raw.Close();
                throw;
            }
            sniffer = raw;
            byte[] localBytes = local.GetAddressBytes();
            new Thread(() => Sniff(raw, localBytes)) { IsBackground = true }.Start();
        }

        void Sniff(Socket raw, byte[] localBytes)
        {
            byte[] buffer = new byte[65535];
            while (true)
            {
                int read;
                try { read = raw.Receive(buffer); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException)
                {
                    lock (sync) if (sniffer != raw) return;
                    Thread.Sleep(50);
                    continue;
                }
                Copy(buffer, read, localBytes);
            }
        }

        void Close(string key)
        {
            Flow flow = flows[key];
            flows.Remove(key);
            relayPorts.Remove(flow.LocalPort);
            flow.Closed = true;
            flow.Socket.Close();
        }

        Flow Open(int clientPort, byte[] clientIp, IPEndPoint server)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.IOControl(SioUdpConnReset, new byte[4], null);
            socket.Bind(new IPEndPoint(local, 0));
            int localPort = ((IPEndPoint)socket.LocalEndPoint).Port;
            Flow flow = new Flow { ClientPort = clientPort, LocalPort = localPort, ClientIp = clientIp, Server = server, Socket = socket, Created = DateTime.UtcNow };
            opened.Enqueue(flow.Created);
            relayPorts.Add(localPort);
            Program.Say("  using fresh port " + localPort + " for " + server);
            new Thread(() => ReadReplies(flow)) { IsBackground = true }.Start();
            return flow;
        }

        void Copy(byte[] p, int length, byte[] localBytes)
        {
            if (length < 28 || (p[0] >> 4) != 4 || p[9] != 17) return;
            int ihl = (p[0] & 15) * 4;
            if (ihl < 20 || length < ihl + 8 || ((p[6] << 8 | p[7]) & 0x3FFF) != 0) return;
            if (p[12] != localBytes[0] || p[13] != localBytes[1] || p[14] != localBytes[2] || p[15] != localBytes[3]) return;
            string server = p[16] + "." + p[17] + "." + p[18] + "." + p[19];
            int clientPort = p[ihl] << 8 | p[ihl + 1];
            int serverPort = p[ihl + 2] << 8 | p[ihl + 3];
            int udpLength = p[ihl + 4] << 8 | p[ihl + 5];
            if (udpLength < 8 || ihl + udpLength > length) return;
            byte[] payload = new byte[udpLength - 8];
            Array.Copy(p, ihl + 8, payload, 0, payload.Length);
            Flow flow;
            lock (sync)
            {
                if (!watched.Contains(server) || relayPorts.Contains(clientPort)) return;
                string key = clientPort + "|" + server + ":" + serverPort;
                if (!flows.TryGetValue(key, out flow))
                {
                    if (flows.Count >= MaxFlows) return;
                    flow = Open(clientPort, (byte[])localBytes.Clone(), new IPEndPoint(IPAddress.Parse(server), serverPort));
                    flows[key] = flow;
                }
                int id = p[4] << 8 | p[5];
                DateTime now = DateTime.UtcNow;
                if (id == flow.LastId && (now - flow.LastSeen).TotalMilliseconds < 100 && payload.SequenceEqual(flow.LastPayload))
                {
                    Duplicates++;
                    return;
                }
                flow.LastId = id;
                flow.LastPayload = payload;
                flow.LastSeen = now;
                Copied++;
                payload = Prepare(flow, payload);
            }
            try
            {
                flow.Socket.SendTo(payload, flow.Server);
                Interlocked.Increment(ref Sent);
            }
            catch (SocketException e)
            {
                Interlocked.Increment(ref SendErrors);
                LastSendError = e.SocketErrorCode;
            }
            catch (ObjectDisposedException) { }
        }

        static byte[] Prepare(Flow flow, byte[] payload)
        {
            if (flow.Replied || !Packets.IsConnect(payload)) return payload;
            if (flow.Unchanged < 3 || (DateTime.UtcNow - flow.Created).TotalSeconds < 3)
            {
                flow.Unchanged++;
                return payload;
            }
            if (flow.Edits >= 12) return payload;
            byte[] edited = Packets.WithFreshSession(payload);
            if (edited == null) return payload;
            if (flow.Edits++ == 0) Program.Say("  no answer yet: asking the server for a fresh session");
            return edited;
        }

        void ReadReplies(Flow flow)
        {
            byte[] buffer = new byte[65535];
            byte[] serverIp = flow.Server.Address.GetAddressBytes();
            while (!flow.Closed)
            {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int read;
                try { read = flow.Socket.ReceiveFrom(buffer, ref from); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException)
                {
                    Thread.Sleep(50);
                    continue;
                }
                if (!from.Equals(flow.Server)) continue;
                Interlocked.Increment(ref Answers);
                if (!flow.Replied)
                {
                    flow.Replied = true;
                    Program.Say("  server answered on the fresh port");
                }
                answeredPorts[flow.ClientPort] = true;
                tunnel.Send(Packets.BuildUdp(serverIp, flow.ClientIp, flow.Server.Port, flow.ClientPort, buffer, read));
            }
        }
    }

    static class Program
    {
        const string WintunSha256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
        static readonly object consoleLock = new object();

        public static void Say(string text)
        {
            lock (consoleLock) Console.WriteLine(DateTime.Now.ToString("HH:mm:ss") + "  " + text);
        }

        public static int Netsh(string arguments, out string output)
        {
            ProcessStartInfo info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "netsh.exe"), arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process process = Process.Start(info))
            {
                output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        static void DisableQuickEdit()
        {
            const int StdInputHandle = -10;
            const uint QuickEditMode = 0x40;
            const uint ExtendedFlags = 0x80;
            IntPtr input = Native.GetStdHandle(StdInputHandle);
            uint mode;
            if (Native.GetConsoleMode(input, out mode)) Native.SetConsoleMode(input, (mode & ~QuickEditMode) | ExtendedFlags);
        }

        static int Main(string[] args)
        {
            Console.Title = "ROB RUN Fix";
            DisableQuickEdit();
            Console.WriteLine("ROB RUN Fix - unofficial helper for battle joins stuck on loading.");
            Console.WriteLine("Only while a join is stuck, it copies the game's packets to that server and sends them from a fresh port.");
            Console.WriteLine("It never touches game files or memory. Unofficial: account safety is not guaranteed.");
            Console.WriteLine();
            int code = Start(args.Contains("--selftest"));
            Console.WriteLine();
            Console.WriteLine("Stopped. Press Enter to close this window.");
            Console.ReadLine();
            return code;
        }

        static int Start(bool selfTest)
        {
            string dll = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "wintun.dll");
            if (!File.Exists(dll) || Sha256(dll) != WintunSha256)
            {
                Say("wintun.dll is missing or is not the official Wintun 0.14.1 file.");
                return 1;
            }
            bool first;
            using (Mutex mutex = new Mutex(true, @"Local\RobRunFix", out first))
            {
                if (!first)
                {
                    Say("Another copy is already running.");
                    return 1;
                }
                Tunnel tunnel = null;
                Relay relay = null;
                try
                {
                    tunnel = new Tunnel();
                    relay = new Relay(tunnel);
                    return selfTest ? SelfTest(relay) : Watch(relay);
                }
                catch (Exception e)
                {
                    Say("Error: " + e.Message);
                    return 2;
                }
                finally
                {
                    if (relay != null) relay.DeactivateAll();
                    if (tunnel != null) tunnel.Dispose();
                }
            }
        }

        static string Sha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
        }

        static int Watch(Relay relay)
        {
            string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), @"AppData\LocalLow\Kefir\ROB RUN\Player.log");
            LogTail tail = new LogTail(log);
            JoinWatcher watcher = new JoinWatcher();
            ManualResetEvent stop = new ManualResetEvent(false);
            Console.CancelKeyPress += (sender, e) => { e.Cancel = true; stop.Set(); };
            new Thread(() => { Console.ReadLine(); stop.Set(); }) { IsBackground = true }.Start();
            Say("Ready. Press Enter to stop (if a battle is running through the fix, leave it first).");
            bool? gameRunning = null;
            DateTime nextGameCheck = DateTime.MinValue;
            while (!stop.WaitOne(100))
            {
                DateTime now = DateTime.UtcNow;
                if (now >= nextGameCheck)
                {
                    nextGameCheck = now.AddSeconds(5);
                    bool running = GameRunning();
                    if (running != gameRunning) Say(running ? "ROB RUN is running. Watching for stuck joins." : "Waiting for ROB RUN to start.");
                    if (!running && relay.Active)
                    {
                        relay.DeactivateAll();
                        Say("Game closed: fix switched off.");
                    }
                    gameRunning = running;
                }
                foreach (string line in tail.ReadNew())
                {
                    LogEvent e = watcher.Feed(line, now);
                    if (e == LogEvent.Connected)
                        Say(relay.AnsweredBy(watcher.ConnectedIp) ? "CONNECTED through the fix (" + watcher.Host + ")" : "Connected directly (" + watcher.Host + ")");
                    else if (e == LogEvent.Dropped)
                        Say("Battle connection dropped; the game is reconnecting.");
                    else if (e == LogEvent.BattleLeft && relay.Active)
                    {
                        relay.DeactivateAll();
                        Say("Left the battle: fix switched off.");
                    }
                }
                if (watcher.StallDue(now))
                {
                    watcher.PendingHandled = true;
                    Repair(relay, watcher);
                }
            }
            return 0;
        }

        static bool GameRunning()
        {
            Process[] found = Process.GetProcessesByName("ROB RUN");
            foreach (Process p in found) p.Dispose();
            return found.Length > 0;
        }

        static void Repair(Relay relay, JoinWatcher watcher)
        {
            List<string> ips = watcher.Addresses.Concat(new[] { watcher.PendingIp }).Distinct().Where(Packets.IsPublic).ToList();
            if (ips.Count == 0) return;
            try
            {
                if (relay.IsWatched(watcher.PendingIp))
                {
                    if (!relay.HasFlows(ips)) Say("Still stuck, and the game's packets are not reaching the fix. " + Counters(relay));
                    else if (relay.Rotate(ips)) Say("Still stuck through the fix: switching to another fresh port. " + Counters(relay));
                    else Say("Hourly port limit reached. If it stays stuck, restart the game.");
                }
                else
                {
                    Say("Join stuck for " + JoinWatcher.StallSeconds + "s on " + watcher.Host + ": sending " + string.Join(", ", ips) + " through a fresh port.");
                    relay.Activate(ips);
                }
            }
            catch (Exception e)
            {
                Say("Could not start the fix: " + e.Message);
            }
        }

        static string Counters(Relay relay)
        {
            return "[copied " + relay.Copied + ", duplicates skipped " + relay.Duplicates + ", sent " + relay.Sent + ", send errors " + relay.SendErrors + (relay.SendErrors > 0 ? " " + relay.LastSendError : "")
                + ", answers " + relay.Answers + "]";
        }

        static Socket NewUdp()
        {
            return new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { ReceiveTimeout = 3000 };
        }

        static int Replies(Socket socket, IPEndPoint to, byte id, int wanted)
        {
            byte[] query = { 0x52, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1 };
            byte[] reply = new byte[512];
            int count = 0;
            try
            {
                if (to == null) socket.Send(query);
                else socket.SendTo(query, to);
                while (count < wanted)
                    if (socket.Receive(reply) > 12 && reply[0] == 0x52 && reply[1] == id) count++;
            }
            catch (SocketException) { }
            return count;
        }

        static bool ThroughFix(Relay relay, Socket socket, IPEndPoint to, byte id)
        {
            return Replies(socket, to, id, 2) == 2 && relay.Answered(((IPEndPoint)socket.LocalEndPoint).Port);
        }

        static int SelfTest(Relay relay)
        {
            const string target = "1.1.1.1";
            IPEndPoint dns = new IPEndPoint(IPAddress.Parse(target), 53);
            Say("Self-test: DNS questions to " + target + ", before and after the fix starts.");
            using (Socket fresh = NewUdp())
            using (Socket connected = NewUdp())
            using (Socket used = NewUdp())
            {
                connected.Connect(dns);
                if (Replies(connected, null, 1, 1) != 1 || Replies(used, dns, 2, 1) != 1)
                {
                    Say("SELF-TEST FAILED: " + target + " does not answer even without the fix (check your internet).");
                    return 1;
                }
                relay.Activate(new List<string> { target });
                bool newSocket = ThroughFix(relay, fresh, dns, 3);
                bool oldConnected = ThroughFix(relay, connected, null, 4);
                bool oldUnconnected = ThroughFix(relay, used, dns, 5);
                relay.DeactivateAll();
                Say("  " + Counters(relay));
                Say("  socket opened after the fix started:          " + (newSocket ? "OK" : "FAILED"));
                Say("  socket opened before it, connected (game-like): " + (oldConnected ? "OK" : "FAILED"));
                Say("  socket opened before it, not connected:         " + (oldUnconnected ? "OK" : "FAILED"));
                bool ok = newSocket && oldConnected && oldUnconnected;
                Say(ok ? "SELF-TEST PASSED: a copy of each packet left through a fresh port and its answer reached the original socket."
                       : "SELF-TEST FAILED: some traffic did not go through the fix.");
                return ok ? 0 : 1;
            }
        }
    }
}
