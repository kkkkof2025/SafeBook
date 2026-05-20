import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

assets = [
    '/SafeBook/',
    '/SafeBook/stylesheets/extra.css',
    '/SafeBook/javascripts/extra.js',
]
for path in assets:
    url = 'https://kkkkof2025.github.io' + path
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        data = resp.read()
        print(path + ': OK ' + str(len(data)) + ' bytes, type=' + resp.headers.get('Content-Type','?'))
    except Exception as e:
        print(path + ': FAIL - ' + str(e))
