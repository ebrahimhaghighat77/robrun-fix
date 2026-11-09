using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace RobRunFix
{
    static class Tests
    {
        static int failures;

        static void Check(bool ok, string name)
        {
            Console.WriteLine((ok ? "PASS  " : "FAIL  ") + name);
            if (!ok) failures++;
        }

        static byte[] Hex(string text)
        {
            return Enumerable.Range(0, text.Length / 2).Select(i => Convert.ToByte(text.Substring(i * 2, 2), 16)).ToArray();
        }

        static uint Fold(uint sum)
        {
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return sum;
        }

        static uint Words(byte[] d, int offset, int length)
        {
            uint s = 0;
            for (int i = 0; i < length; i += 2) s += (uint)(d[offset + i] << 8 | (i + 1 < length ? d[offset + i + 1] : 0));
            return s;
        }

        static int Main(string[] args)
        {
            Check(Packets.Crc32(Encoding.ASCII.GetBytes("123456789")) == 0xCBF43926u, "crc32 matches the standard check value");
            byte[] connect = Hex("8fff123409c320b082ff00010000020200000570000000000200000000000000000000000000000000000000005445535400000000");
            byte[] expected = Hex("8fff12341166c1f582ff00010000ffff00000570000000000200000000000000000000000000000000000000005445535400000000");
            Check(Packets.IsConnect(connect), "zlib-made connect packet is recognised");
            byte[] fresh = Packets.WithFreshSession(connect);
            Check(fresh != null && fresh.SequenceEqual(expected), "fresh-session edit equals the zlib reference byte for byte");
            Check(connect[14] == 2 && connect[15] == 2, "original packet is not modified");
            Check(Packets.WithFreshSession(fresh) == null, "already-fresh packet is left alone");
            for (int i = 0; i < connect.Length; i++)
            {
                byte[] broken = (byte[])connect.Clone();
                broken[i] ^= 1;
                if (Packets.IsConnect(broken)) { Check(false, "flipping byte " + i + " must be rejected"); break; }
                if (i == connect.Length - 1) Check(true, "any single changed byte is rejected");
            }
            Check(!Packets.IsConnect(new byte[60]) && !Packets.IsConnect(new byte[53]), "other packets are rejected");

            byte[] udp = Packets.BuildUdp(new byte[] { 45, 82, 160, 89 }, new byte[] { 198, 18, 99, 1 }, 36705, 50000, new byte[] { 1, 2, 3, 9, 9 }, 3);
            Check(udp.Length == 31 && udp[24] == 0 && udp[25] == 11, "udp packet length uses only the given payload length");
            Check(Fold(Words(udp, 0, 20)) == 0xFFFF, "ipv4 header checksum verifies");
            uint pseudo = Words(udp, 12, 8) + 17 + 11;
            Check(Fold(pseudo + Words(udp, 20, 11)) == 0xFFFF, "udp checksum verifies (odd length)");

            Check(Packets.IsPublic("45.82.160.89") && Packets.IsPublic("5.188.178.115"), "game servers count as public");
            Check(!Packets.IsPublic("192.168.0.1") && !Packets.IsPublic("10.1.1.1") && !Packets.IsPublic("198.18.99.1") && !Packets.IsPublic("127.0.0.1") && !Packets.IsPublic("172.20.0.1") && !Packets.IsPublic("garbage"), "private and invalid addresses are refused");

            TestTail();
            if (args.Length > 0) Replay(args[0]);
            Console.WriteLine(failures == 0 ? "ALL PASSED" : failures + " FAILED");
            return failures;
        }

        static void TestTail()
        {
            string path = Path.GetTempFileName();
            try
            {
                File.WriteAllText(path, "old line\n");
                LogTail tail = new LogTail(path);
                Check(tail.ReadNew().Count == 0, "tail starts at the end of the existing log");
                File.AppendAllText(path, "first\r\nsec");
                List<string> a = tail.ReadNew();
                File.AppendAllText(path, "ond\n");
                List<string> b = tail.ReadNew();
                Check(a.SequenceEqual(new[] { "first" }) && b.SequenceEqual(new[] { "second" }), "tail joins a line split across reads and strips CR");
                File.WriteAllText(path, "new\n");
                Check(tail.ReadNew().SequenceEqual(new[] { "new" }), "tail follows a restarted (shorter) log");
            }
            finally { File.Delete(path); }
        }

        static void Replay(string path)
        {
            Regex stamp = new Regex(@"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\] \[\d+\]");
            JoinWatcher watcher = new JoinWatcher();
            HashSet<string> routed = new HashSet<string>();
            DateTime now = DateTime.MinValue;
            int activations = 0, rotations = 0, viaFix = 0, direct = 0;
            Console.WriteLine("--- replay of " + Path.GetFileName(path) + " (simulated actions) ---");
            foreach (string raw in File.ReadLines(path, Encoding.GetEncoding(28591)))
            {
                string line = raw.TrimEnd('\r');
                Match m = stamp.Match(line);
                if (m.Success) now = DateTime.ParseExact(m.Groups[1].Value, "yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
                if (now == DateTime.MinValue) continue;
                if (watcher.StallDue(now))
                {
                    watcher.PendingHandled = true;
                    List<string> ips = watcher.Addresses.Concat(new[] { watcher.PendingIp }).Distinct().Where(Packets.IsPublic).ToList();
                    if (routed.Contains(watcher.PendingIp)) { rotations++; Print(now, "stuck again -> new fresh port"); }
                    else { activations++; ips.ForEach(ip => routed.Add(ip)); Print(now, "STUCK " + (now - watcher.PendingSince).TotalSeconds.ToString("0.0") + "s -> route " + string.Join(", ", ips)); }
                }
                LogEvent e = watcher.Feed(line, now);
                if (e == LogEvent.Connected)
                {
                    bool fix = routed.Contains(watcher.ConnectedIp);
                    if (fix) viaFix++; else direct++;
                    if (fix || routed.Count > 0) Print(now, (fix ? "connected via fix " : "connected direct ") + watcher.ConnectedIp);
                }
                else if (e == LogEvent.BattleLeft && routed.Count > 0) { routed.Clear(); Print(now, "left battle -> routes removed"); }
            }
            Console.WriteLine("activations=" + activations + " rotations=" + rotations + " connects_via_fix=" + viaFix + " connects_direct=" + direct);
            Check(activations > 0, "replay: the stuck joins in this log trigger the fix");
        }

        static void Print(DateTime t, string text) { Console.WriteLine("  " + t.ToString("HH:mm:ss.fff") + "  " + text); }
    }
}
