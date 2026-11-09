# RobRunFix

A small Windows helper for ROB RUN battle joins that get stuck on the loading screen.

> [!WARNING]
> **Use at your own risk.**
>
> - This is an **unofficial** tool. It is not made, approved or supported by Kefir or Easy Anti-Cheat.
> - **It could get your account banned.** Nobody can promise that it is compatible with the game's anti-cheat.
> - It needs **administrator rights**, creates a virtual network adapter and reads your network traffic to the game server.
> - It may fail, or disconnect you.
> - It has only been tested on a small number of joins on one PC.
>
> If you are not comfortable with these risks, do not use it. Restarting the game also fixes a stuck join (see [If it does not help](#if-it-does-not-help)).

## The problem

The game opens one UDP connection for battle servers when it starts and keeps using it for every battle. Sometimes the battle server stops answering that connection. From then on, every join to that server hangs on the loading screen until the game is restarted. In the game log (`Player.log`) this shows up as `PeerConnect failed id=battle`, repeating.

## How it works

1. RobRunFix follows the game log and waits.
2. When a battle connection attempt has not completed after **2 seconds**, it starts working for that server (both its direct and its proxy address).
3. It **reads** the game's outgoing UDP packets to that server using Windows' built-in packet capture (a raw socket with `SIO_RCVALL`). The original packets are not changed or blocked.
4. It sends a copy of each packet to the server from a **new local port**.
5. The server's replies are handed to the game's own connection through a virtual network adapter (Wintun).
6. If the server still does not answer the new port, only the copy of the *connect request* is changed: its two session ID bytes are set to `0xFF`, which is what a freshly started game sends. No other packet is modified.
7. If the join is still stuck on the game's next attempt, another new port is tried (at most 60 new ports per hour).
8. When you leave the battle or close the game, it stops.

It does **not** read or change game files, game memory or the game process. It does not change your network routes or the settings of your real network adapter. The only thing it reads from the game is the log file. It sends nothing anywhere except the copies of the game's own packets (and, in the self-test, one DNS question to `1.1.1.1`).

## Requirements

- Windows 10 or 11, 64-bit
- .NET Framework 4.x (included with Windows)
- Administrator rights

## Usage

1. Download `RobRunFix.zip` from the [latest release](../../releases/latest) and extract it.
2. Run **`SELFTEST.cmd`** once and accept the administrator prompt. It sends a DNS question to `1.1.1.1` through the same path the game will use. You should see `SELF-TEST PASSED` with all three lines `OK`.
3. When you play, run **`RobRunFix.exe`** (it asks for administrator rights) and keep its window open. You can start it before or after the game.
4. To stop it, **leave the battle first**, then press Enter in its window.

### What the window shows

| Message | Meaning |
|--|--|
| `Join stuck for 2s on ...: sending ... through a fresh port` | A join was stuck and the fix started. |
| `using fresh port N for ...` | Copies of the game's packets are being sent from port `N`. |
| `server answered on the fresh port` | The server replied on the new port. |
| `CONNECTED through the fix` | The game connected with the fix's help. |
| `Connected directly` | The game connected on its own. |
| `Still stuck ...` | The attempt did not work; a new port will be tried. |

Tip: the window runs as administrator. While it has focus, the Windows screenshot shortcut (`Win+Shift+S`) may not react. Click somewhere else first.

## If it does not help

Close the game completely and start it again. The game then opens a new connection, which also clears the stuck state.

## Limitations

- While it is active, the game's packets reach the server twice: once from the old port, which the server ignores, and once from the new port.
- On the tested PC, Windows' packet capture delivered every outgoing packet three times. Exact duplicates are filtered out before copying.
- If a battle is running through the fix and you close RobRunFix, that battle connection will drop.
- IPv6 and fragmented packets are not handled.

## Verify the download

Each release lists the SHA-256 of `RobRunFix.zip`. To check it:

```powershell
Get-FileHash .\RobRunFix.zip -Algorithm SHA256
```

The program refuses to start if `wintun.dll` is not the official Wintun 0.14.1 (amd64) file. The executable is not code-signed. If you prefer, build it yourself.

## Build from source

No SDK is needed. The C# compiler that ships with Windows is enough.

```bat
build.cmd
```

This creates `dist\RobRunFix\` and `dist\RobRunFix.zip`. To run the unit tests:

```bat
test.cmd
```

You can pass a path to a `Player.log` to `test.cmd` to replay a real log through the stall detector.

## License

RobRunFix is released under the [MIT License](LICENSE).

`vendor/wintun/wintun.dll` is the unmodified Wintun 0.14.1 driver library, used only through its public API. It is distributed under its own license, see [vendor/wintun/LICENSE.txt](vendor/wintun/LICENSE.txt). Source: [wintun.net](https://www.wintun.net/).

ROB RUN is a trademark of its owners. This project is not affiliated with them.
