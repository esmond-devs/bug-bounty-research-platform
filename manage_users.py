"""Local admin bootstrap. Avoid passing passwords as command-line arguments."""
import argparse
import getpass
from bbplatform.approvals import connect
from bbplatform.identity import init, create_user

p = argparse.ArgumentParser()
p.add_argument("--db", default="state/approvals.sqlite3")
p.add_argument("--username", required=True)
p.add_argument("--role", choices=("researcher", "reviewer", "admin"), required=True)
args = p.parse_args()
db = connect(args.db)
init(db)
password = getpass.getpass("New password (14+ characters): ")
create_user(db, args.username, password, args.role)
print("Created local account:", args.username)
