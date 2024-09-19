On one side:
```
nc -u 127.0.0.1 11111 # UDP SEND
```

On the other side:
```
nc -ul 11111 # Listening on port 11111
```

See what happens when eBPF program is loaded/not.