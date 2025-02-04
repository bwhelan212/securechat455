from flask import Flask, render_template
from flask_socketio import SocketIO

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret!'
    socketio.init_app(app)
    
    @app.route("/")
    def home():
        return render_template('index.html')
    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app)
# from flask import Flask
# app = Flask(__name__)

# @app.route("/")
# def home():
#     return "Hello, Flask!"

# source .venv/bin/activate
# python -m flask run