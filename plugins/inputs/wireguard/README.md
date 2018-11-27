#### Permissions

**Sudo privileges**
```toml
[[inputs.wireguard]]
  use_sudo = true
```

```bash
$ visudo
# Add the following
telegraf ALL=(ALL) NOPASSWD: /usr/bin/wg show
```
