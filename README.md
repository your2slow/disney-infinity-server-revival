# Disney Infinity 3.0 Online Server (Wii U)

A replacement for Disney's online services in Disney Infinity 3.0 on Wii U. Disney shut the official servers down years ago, so this brings back the online side of the game: accounts, Toy Box sharing, Community Content and the rest.

It's a single Flask server written in Python. It was built by reverse engineering the game and checking what it actually sends and expects, so it isn't guesswork. Eventually this will be rewritten into another language if I ever decide to go public with this server.

## What works

- Creating and signing in to a Disney account, plus auto sign-in from your console
- Uploading, downloading, editing and deleting Toy Boxes (cloud saves)
- Community Content: browsing, search, sorting, trending, likes and downloads
- Toy Box Theater
- Leaderboards (scores and time trials, daily/weekly/monthly/all time, friends)
- Prestige levels, titles and weekly objectives
- Profile and stats saving
- News ticker (with images) and the inbox
- Text Toy filtering
- Friends list (shows Nintendo friends who also have an account on the server)
- Radio Disney and Toy Box TV (need your own media, see below)

## What doesn't

- Trial toys
- Featured Toy Boxes are never picked automatically
- Password reset doesn't send any emails

## Important: online multiplayer is NOT included

**This repo is only the Disney side of the game.** Online multiplayer, invites and joining friends all go through a **Nintendo NEX game server**, which is a different thing, and **this repo does not have one.**

To play online with other people you need a Disney Infinity 3.0 NEX game server set up separately. Im currently in the process of making a functional one with matchmaking.

## Requirements

- Python 3.9 or newer and Flask (`pip install flask`)
- a Wii U with Disney Infinity 3.0 **and the latest update installed**
- A homebrew setup (Aroma) with FTP access
- A patched game RPX that points the game at your server instead of Disney's

## Setup

1. **Run the server.**
   ```
   python infinity_server.py
   ```
   It runs on port 80 by default (set `PORT` to change it). `infinity.db` and `requests.log` get created automatically if they're missing.

2. **Patch the game.** The game has Disney's addresses built in, so they need to be changed to your server's address (for example `http://192.168.1.50`). Patch the **update's** RPX, not the base game's. When an update is installed, the console runs the update's copy.

3. **Put the patched RPX on the console.** WUP Installer won't do it, because it ignores the `code` folder. Use FTP and replace the file in:
   ```
   /storage_mlc/usr/title/0005000e/101ac900/code/
   ```
   (or `/storage_usb/...` if the game is on USB). Back up the original first.

4. **Start the game.** You should see requests show up in `requests.log` right away

## Optional content

All of these are just folders or files next to the server:

| What | Where |
|---|---|
| News ticker | `news.json`, with images in `news/` (PNG only) |
| Radio Disney | MP3s in `radio/` (all the same sample rate) |
| Toy Box TV | `.bk2` videos in `videos/toyboxTV/` etc. |
| Theater posters | `cdn/posters/THEATRE_1.png` ... `THEATRE_11.png` |
| Theater screens | `theatre.json` to pin Toy Boxes to each screen |
| Prestige icons | `cdn/prestige/level_1.png` ... or `default.png` |
| Extra word filter | `moderation.txt`, one word per line |

The Wii U has its own swear filter that runs before anything reaches the server, so `moderation.txt` only adds to it.

## Privacy

`infinity.db` stores accounts (passwords are hashed), Toy Boxes and stats. `requests.log` logs every request in full, **including passwords typed during sign-up**. Don't share either of them publicly.

## Disclaimer

This is a fan project. It's not affiliated with, endorsed by or connected to Disney or Avalanche Software in any way. Disney and Disney Infinity are trademarks of Disney. No game code, assets or copyrighted content are included here. You need your own copy of the game.

## License

MIT. See `LICENSE`.
