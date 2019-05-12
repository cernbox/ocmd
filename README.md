# ocmd
OpenCloudMesh Daemon


## Before hacking

- Install latest golang version
- Install [dep](https://github.com/golang/dep)
- cd into git clone of [github.com/cernbox/ocmd]
- Run dep ensure
- You should be able to `go build`


## Run
- `go build`
- `echo "log-level: debug" > ocmd.yaml`
- Put some test domains in /etc/hosts to work from the same box.

```
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4 nasa.com airbus.com
```


```
./ocmd --user-manager-memory-identities "gonzalhu@nasa.com" --provider-authorizer-memory-domains "airbus.com.::http://airbus.com:7777/ocm" --tcp-address localhost:8888
./ocmd --user-manager-memory-identities "kuba@airbus.com" --provider-authorizer-memory-domains "nasa.com::http://nasa.com.:8888/ocm" --tcp-address localhost:7777
```

## Play

Trigger an internal share request as user kuba to the airbus instance, that will forward the request to the other OCM instance.

```
curl -i http://localhost:7777/internal/shares -X POST  --data-binary @new-internal-share-req.json  -H "Remote-User: kuba@airbus.com" 
```

## TODO

Implement the **api/internal_share_manager_python** and **api/share_manager_python** plugins.

Use **--internal-share-manager "python"** and **--share-manager "python"** flags to load these plugins.

See `./ocmd -h` for more help.

## CONFIG PROVIDER

curl -X POST -d "domain=XXX" localhost:9994/internal/providers -w "%{http_code}\n"