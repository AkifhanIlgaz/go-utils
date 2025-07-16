## Generate Private Key

```bash
openssl genrsa -out private_key.pem 2048
```

## Generate Public Key

```bash
openssl rsa -in private_key.pem -pubout -out public_key.pem
```