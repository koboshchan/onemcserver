# onemcserver

DEPRECATED: This project is no longer maintained. Please use [OneMcServerVelocity](https://github.com/koboshchan/OneMcServerVelocity) instead.

oneserver but for minecraft.

have you ever wanted to host multiple minecraft servers on one ip but don't want to deal with the hassle of remembering which port each server is on? well, this is the solution for you! with onemcserver, you can host multiple minecraft servers on one machine and have them all accessible through the same ip, via domain names or subdomains. simply edit the config.json file to add your servers and their forwarding ip and ports, and you're good to go!

supported versions: 1.20.5+

support subdomain wildcard: if you dont want to add A records for each domain, you can add a wildcard A record that point to your server's ip, for example, *.example.com. then you can add any subdomain to the config.json file, for example, server1.example.com, server2.example.com, etc.

make sure to also expose port of onemcserver (default: 25565) and your forwarding servers in your router and firewall.

## Configuration

Edit `config.json` to define your domain mappings:

```json
{
    "servers": [
        {
            "host": "play.example.com",
            "transfer_to": [
                "12.34.56.78",
                25565
            ],
            "cracked_players": true
        }
    ],
    "private_key": "",
    "public_key": "",
    "port": 25565,
    "translations": {
        "domain.unknown.disconnect": "Unknown domain: %s",
        "domain.unknown.motd": "Unknown Domain",
        "server.offline.motd": "The server is currently offline.",
        "authentication.failed.disconnect": "That name is registered to a premium account. Please log in with your official account. Or restart your client to try again.",
        "token.invalid.disconnect": "Invalid verify token. Please restart your client and try again.",
        "online.mode.disconnect": "This server is in Online Mode. Please log in with your official account. Or restart your client to try again."
    }
}
```

- **host**: The domain name players use to connect.
- **transfer_to**: The target IP/Domain and Port to redirect the player to.
- **cracked_players**: Set to `true` to allow offline-mode players, or `false` to enforce Mojang authentication.

## Usage

1. Install requirements:
   `pip install -r requirements.txt`

2. Run the server:
   `python main.py`

Docker: `docker compose up -d --build` (make sure to edit the config.json file before running this command).
