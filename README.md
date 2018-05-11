# ocmd
OpenCloudMesh Daemon


## Before hacking

- Install latest golang version
- Install [dep](https://github.com/golang/dep)
- cd into git clone of [github.com/cernbox/ocmd]
- Run dep ensure
- You should be able to `go build`


## Run
- `touch ocmd.yaml`
- ./ocmd  &
- `curl localhost:8888/ocm/shares -X POST -i --data-binary @new-share-incoming.json ` 
