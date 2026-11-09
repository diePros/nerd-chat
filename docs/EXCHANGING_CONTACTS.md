# Exchanging contact files safely

A **contact file** (also called a bundle, `.sbc`) is what you give someone so that you can talk to each other. Read this before you
send one over a chat app, e-mail or social network.

## The short version
1. **Best: no file at all.** Use one-time-code pairing. Over Tor (`T` creates a link and a code, `J` joins with them; works anywhere, no shared network; the GUI calls it "Over the internet") or on one network (`l` / `c`, see GETTING_STARTED.md §4). Send the LINK to your partner only, and tell the CODE by voice or in person, never in the same message.
2. **Next best: hand it over in person**, on a USB stick or by connecting the two computers directly. Delete the file afterwards.
3. **If you must send it remotely**, use the safest channel you have (see the table), and then ALWAYS compare the safety number on a
   DIFFERENT channel: by voice or in person, never in the same chat the file travelled through.
4. **Do not send it over Discord, Telegram (cloud chats), WhatsApp, Instagram, Facebook, Slack, e-mail or a public file host** unless you accept
   everything under "Why a chat platform is a bad channel" below.

## What is in a contact file
Only public keys and addresses: your identity keys, and the onion address and authorisation key for THIS one contact. It contains no
password and no private key, so a leaked file cannot read your messages or pretend to be you.

It is still **not public**:
- Whoever holds the file can look up **when your onion service is online**, for as long as that address exists, even if they cannot connect.
  That is only the case where you host for that contact; the contact details show who hosts. (Details: docs/TRANSPORT.md.)
- It shows that **you** know the person you are sending it to, and when.

## Why a chat platform is a bad channel
- **The platform keeps it.** The file sits in the chat history and in the operator's storage, backups and logs, usually for good, even after
  you delete the message. It is tied to your real account, your phone number or e-mail, and your IP address.
- **It records the relationship.** "A sent a contact file to B at this time" is exactly what the app is built to avoid revealing.
- **Anyone with access can read the online times.** The operator, anyone who gets into either account, or whoever gets a backup can use
  the onion address in the file to see when you are online.
- **It can be swapped.** A platform, or someone who has taken over an account, can replace the file with their own. You would then be talking to
  them while thinking it is your friend. Only the safety-number check below catches that. The platform is the very party you do not want deciding what you receive.

## Channels, from better to worse
| Channel | Verdict |
|---|---|
| One-time-code pairing in person (`l` / `c`) | Best: no file, no platform, the code proves the other person. |
| USB stick or direct cable, handed over in person | Very good. Delete the file from the stick afterwards. |
| An end-to-end encrypted messenger with disappearing messages | Weaker: the operator still sees who talks to whom and when. Only with the safety-number check, by voice. |
| Cloud chats, Discord, e-mail, social media, public file hosts | **Not recommended.** See above. |

## After the file arrived: the safety-number check (do not skip it)
1. Import the file (`I`). The contact shows **UNVERIFIED** and a safety number.
2. **Call the person or meet them** and read the safety number to each other (`v` on both sides). Use a different channel than the one
   the file came through. If the numbers differ, **stop**: someone changed a file on the way. Delete the contact (`d`) and start again over a safer channel.
3. If they match, press `y`. The contact is now verified.

You can chat with an unverified contact (the app warns you), but until the numbers have been compared you cannot be sure who is on the other end.

## Clean up
- Delete the file from the chat, the download folder and the USB stick when it has been imported. Deleting is not the same as erasing:
  the platform's copy remains.
- `Ctrl+]` (purge) also overwrites the files this session exported. Files you imported, and files exported in earlier sessions, stay.
- If a file went over a channel you now distrust, use key rotation (`K`, docs/KEY_ROTATION.md): old copies of your file then stop showing when you are online.
