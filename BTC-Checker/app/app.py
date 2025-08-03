from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>BTC Checker</title></head>
    <body>
        <h1>BTC Checker läuft!</h1>
        <p>Weboberfläche erfolgreich geladen.</p>
    </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=34277)
