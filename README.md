# JWT Rewrite

JWT Rewrite is a middleware plugin for [Traefik](https://github.com/containous/traefik) 
which verifies a jwt token and rewrites a new jwt for further authentication

Inspired and modified from https://github.com/23deg/jwt-middleware

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-rewrite.modulename=github.com/irotem/jwt-rewrite"
  - "--experimental.plugins.jwt-rewrite.version=v0.1"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-rewrite:
      plugin:
        jwt-rewrite:
          hash: HS256
          verify:
            secret: SECRET
            authHeader: Authorization
            headerPrefix: Bearer
          sign:
            secret: SECRET
            authHeader: Authorization
            headerPrefix: Bearer  
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-rewrite@prodvider"
```
