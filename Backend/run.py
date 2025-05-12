import os
from app import create_app

if __name__ == '__main__':
    # Get environment variables
    env = os.environ.get('FLASK_ENV', 'development')
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

    app = create_app(env)
    app.run(host=host, port=port, debug=debug, use_reloader=False)