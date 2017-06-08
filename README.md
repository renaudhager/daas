# DHCP As A Service.
This is a small Flask app, to manage DHCP leases (host leases).

This allows you:
* create host lease.
* delete host lease.
* lookup for host lease.
* register a node into KV to generate a token.
* unregister a node from the KV.

There is a small authentication mechanism using pre generated token store in KV (consul for now.)

This use OMAPI to interact with DHCP server, so you have to configure DHCP servers accordingly to use this.

## Configuration
Default configuration is /etc/daas.conf

There is 3 sections :
* Consul : consul configuration (host, port ....).
* OMAPI : OMAPI configuration (port, keyname, secret ...).
* DCHP Servers : list of dhcp server map to your domain.


## Queries

* register a node :
```
curl -X POST "http://daas.vagrant.lan/register?fqdn=test01.vagrant.lan"
```

* unregister a node :
```
curl -X POST "http://daas.vagrant.lan/unregister?fqdn=test01.vagrant.lan&token=638d20ed9ab8250b58c91e9c0a2f7336ed76962c543a4003227f12567deba36b"
```

* create a lease :
```
curl -X POST "http://daas.vagrant.lan/create?fqdn=test01.vagrant.lan&ip=172.16.10.25&mac=08:00:27:31:dd:fe&token=638d20ed9ab8250b58c91e9c0a2f7336ed76962c543a4003227f12567deba36b"
```

* delete a lease :
```
curl -X POST "http://daas.vagrant.lan/delete?fqdn=test01.vagrant.lan&token=638d20ed9ab8250b58c91e9c0a2f7336ed76962c543a4003227f12567deba36b"
```

* lookup for a lease:
```
curl -X GET "http://daas.vagrant.lan/lookup?fqdn=test01.vagrant.lan"
```

## Requirements
See requirements.txt

## Limitations
* Right now the OMAPI configuration (port, key, secret) need to be the same on DHCP servers.
* Only on KV is supported.
