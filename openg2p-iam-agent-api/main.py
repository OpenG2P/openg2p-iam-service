import sys

from openg2p_iam_agent_api.app import Initializer

initializer = Initializer()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        initializer.migrate_database(sys.argv[2:])
    else:
        initializer.main()
else:
    app = initializer.return_app()
