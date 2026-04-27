"""Entry point: python -m apparmor_language_server [--tcp] [--host HOST] [--port PORT]"""

from .server import main

if __name__ == "__main__":
    main()
