<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="theme-color" content="#111111">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="keywords" content="stypr, Harold Kim, gpg.harold.kim">
    <meta name="google" content="notranslate">
    <meta name="theme-color" content="#333333">
    <meta name="referrer" content="no-referrer">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
    <meta name="description" content="Harold Kim: gpg">

    <title>gpg.harold.kim</title>
    <style>
        body { font-family: "SUIT Variable", sans-serif; background: #111; color: #fff; }
        code, pre { font-family: "Oxygen Mono", monospace; font-size: 10pt; }
        code.smaller { font-size: 7pt; white-space: normal; cursor: pointer; }
        .none { display: none; }
        a { color: #eee; }
        div.container { max-width: 1200px; margin: 0 auto; }
        ::-webkit-scrollbar { width: 13px; }
        ::-webkit-scrollbar-track { background-color: #111; }
        ::-webkit-scrollbar-thumb { background-image: linear-gradient(180deg, #999 0%, #aaa 99%); box-shadow: inset 2px 2px 5px 0 rgba(255,255,255,0.5); }
    </style>
</head>

<body>
	<div class="container">
        <h1>gpg.harold.kim</h1>
        <p>
            Use GPG for sending confidential messages and contents.
            (<a href="//github.com/stypr/gpg-validator">sourcecode</a>)
        </p>
        <h2>Keys</h2>
        <ul>
            <li>
                <code>B43975C459ED7A46</code> <a href="/keys/root.pub.asc">/keys/root.pub.asc</a><br>
                <code title="sha256sum" class="smaller">6e8e60ae3b41a81e8b5c5469b2c8afa92bf72f2b124ce519e736632c9c85245a</code><br>
                <ul>
                    <li>
                        <code>87C4CD66A509906B</code> <a href="/keys/general.pub.asc">/keys/general.pub.asc</a>
                    </li>
                    <li><code>F01CD491240E43A6</code> <a href="/keys/confidential.pub.asc">/keys/confidential.pub.asc</a></li>
                </ul>
            </li>
        </ul>
        <h2>Validator</h2>
        The result should NEVER DISPLAY IN <span style="color: red">RED COLOR</span>.<br>
        Validator reduces the attack surface, but this does not mean <a href="//robertchen.cc/blog/2021/04/03/github-pages-xss">it's completely secure</a>.<br>
        <ul>
            <li><code>Checksums match: <noscript>[You must enable JavaScript to compare checksums.]</noscript><span class="checksum-result">...</span></code></li>
            <li><code>Keyserver match: <noscript>[You must enable JavaScript to compare public keys with keyservers]</noscript><span class="keyserver-result">...</span></code></li>
        </ul>
        <h2>Contact</h2>
        <ul>
            <li><a href="//harold.kim">Email</a></li>
            <li><a href="//t.me/stypr">Telegram</a></li>
        </ul>
        <br>
        <i>a <a href="//validator.w3.org/nu/?doc=https%3A%2F%2Fharold.kim%2F">W3C validated</a> website.</i>
    </div>

    <script src="/sha512.js"></script>
    <script src="/openpgp.min.js"></script>
    <script src="/validator.js"></script>
</body>
</html>
