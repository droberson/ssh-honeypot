# SSH Honeypot Docker

### Build and Deploy

To build: 

```
docker-compose build
```

To run: 

```
docker-compose -p ssh-honeypot up
```



### Environment variables

Certain amount of control is given through following environment variables

```
- SSH_BANNER                          # Value set here will be passed as -b argument to the service
- SSH_BANNER_INDEX                    # Value set here will be passed as -i argument to the service
- SSH_JSON_LOG_SERVER                 # Value set here will be passed as -J argument to the service
- SSH_JSON_LOG_SERVER_PORT            # Value set here will be passed as -P argument to the service
```



### Volumes

Following paths are mounted as volumes by default

```
- /home/honeycomb/log       # Log files
- /home/honeycomb/rsa       # Generated RSA key is held here. If you have your own key, you can replace sshd-key.rsa file
```

* As per docker support, any additional path(s) can be mounted as volume(s); Note that this could have side-effects.
* RSA key is generated during stage 2. If file already exists, it will not be generated again. 