# onemcserver

oneserver but for minecraft.

have you ever wanted to host multiple minecraft servers on one ip but don't want to deal with the hassle of remembering which port each server is on? well, this is the solution for you! with onemcserver, you can host multiple minecraft servers on one machine and have them all accessible through the same ip, via domain names or subdomains. simply edit the config.json file to add your servers and their forwarding ip and ports, and you're good to go!

supported versions: 1.20.5+

support subdomain wildcard: if you dont want to add A records for each domain, you can add a wildcard A record that point to your server's ip, for example, *.example.com. then you can add any subdomain to the config.json file, for example, server1.example.com, server2.example.com, etc.

make sure to also expose port of onemcserver (default: 25565) and your forwarding servers in your router and firewall.

## Usage

`python main.py`. all libraries are python built in, so no need to install anything. you can edit the config.json file to change the server's settings. {"server_domain":["forwarding_domain", forwarding_port]}.

docker: `docker compose up -d --build` (make sure to edit the config.json file before running this command).