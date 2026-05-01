import os
import re

endpoints = {
    'login': 'auth.login',
    'register': 'auth.register',
    'verify_otp': 'auth.verify_otp',
    'resend_otp': 'auth.resend_otp',
    'logout': 'auth.logout',
    'change_password': 'auth.change_password',
    'get_private_key': 'auth.get_private_key',
    'download_private_key': 'auth.download_private_key',
    'download_public_key': 'auth.download_public_key',

    'index': 'file.index',
    'dashboard': 'file.dashboard',
    'upload_file': 'file.upload_file',
    'download_file': 'file.download_file',
    'my_files': 'file.my_files',
    'shared_with_me': 'file.shared_with_me',
    'security_page': 'file.security_page',
    'verify_signature_standalone': 'file.verify_signature_standalone',
    'upload_page': 'file.upload_page',

    'admin_dashboard': 'admin.admin_dashboard',
    'create_organization': 'admin.create_organization',
    'list_organizations': 'admin.list_organizations',
    'request_join': 'admin.request_join',
    'approve_user': 'admin.approve_user',
    'reject_user': 'admin.reject_user',
    'remove_user': 'admin.remove_user',
    'open_storage': 'admin.open_storage',
    'download_raw': 'admin.download_raw',
}

tmpl_dir = 'e:/secure_file_sharing/templates'
count = 0

for root, _, files in os.walk(tmpl_dir):
    for f in files:
        if f.endswith('.html'):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            for old, new in endpoints.items():
                content = re.sub(rf"url_for\(['\"]{old}['\"]", f"url_for('{new}'", content)
                
            with open(path, 'w', encoding='utf-8') as file:
                file.write(content)
            count += 1
print(f"Updated {count} templates.")
