"""Host-side account administration. Run with access to the private auth database."""
import argparse
import getpass
import sqlite3

import pyotp
from werkzeug.security import generate_password_hash

from .auth import AuthStore
from .config import MonitorConfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['add', 'password', 'role', 'disable', 'enable', 'mfa', 'disable-mfa', 'list'])
    parser.add_argument('username', nargs='?')
    parser.add_argument('--role', choices=['viewer', 'operator'], default='viewer')
    args = parser.parse_args()
    store = AuthStore(MonitorConfig.from_env().auth_db)
    if args.command != 'list' and not args.username:
        parser.error('username is required')
    try:
        if args.command in {'add', 'password'}:
            password = getpass.getpass('Password (at least 12 characters): ')
            if password != getpass.getpass('Confirm password: '):
                raise ValueError('Passwords did not match')
            store.validate_password(password)
            if args.command == 'add':
                store.add_user(args.username, password, args.role)
            else:
                store.update_user(args.username, password_hash=generate_password_hash(password))
        elif args.command == 'role':
            store.update_user(args.username, role=args.role)
        elif args.command in {'disable', 'enable'}:
            store.update_user(args.username, enabled=int(args.command == 'enable'))
        elif args.command == 'mfa':
            if not any(u['username'] == args.username for u in store.users()):
                raise ValueError('Unknown account')
            secret = pyotp.random_base32()
            print('Add this private enrollment URI to your authenticator; do not share it:')
            print(pyotp.TOTP(secret).provisioning_uri(args.username, issuer_name='Oma monitor'))
            code = getpass.getpass('Current authenticator code: ')
            if not pyotp.TOTP(secret).verify(code):
                raise ValueError('Invalid code; MFA was not enabled')
            store.update_user(args.username, totp_secret=secret, last_totp=-1)
        elif args.command == 'disable-mfa':
            store.update_user(args.username, totp_secret=None, last_totp=-1)
        else:
            for user in store.users():
                print(f"{user['username']} role={user['role']} enabled={bool(user['enabled'])} mfa={bool(user['mfa'])}")
    except (ValueError, sqlite3.IntegrityError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
